rule TTP_XOR_QUAD_CurrentVersionRun_38e8 {
  strings:
    $key_38e8 = { 6b 87 [2] 4f 89 [2] 64 a5 [2] 4a 87 [2] 5e 9c [2] 51 86 [2] 4f 9b [2] 4d 9a [2] 56 9c [2] 4a 9b [2] 56 b4 }

  condition:
    any of them
}