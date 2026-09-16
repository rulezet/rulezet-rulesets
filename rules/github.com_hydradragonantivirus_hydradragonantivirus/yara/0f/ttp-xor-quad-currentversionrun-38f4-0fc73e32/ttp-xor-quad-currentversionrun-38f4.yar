rule TTP_XOR_QUAD_CurrentVersionRun_38f4 {
  strings:
    $key_38f4 = { 6b 9b [2] 4f 95 [2] 64 b9 [2] 4a 9b [2] 5e 80 [2] 51 9a [2] 4f 87 [2] 4d 86 [2] 56 80 [2] 4a 87 [2] 56 a8 }

  condition:
    any of them
}