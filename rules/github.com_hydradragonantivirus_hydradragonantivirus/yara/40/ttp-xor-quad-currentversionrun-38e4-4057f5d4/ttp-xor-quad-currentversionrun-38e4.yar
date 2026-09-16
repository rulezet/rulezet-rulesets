rule TTP_XOR_QUAD_CurrentVersionRun_38e4 {
  strings:
    $key_38e4 = { 6b 8b [2] 4f 85 [2] 64 a9 [2] 4a 8b [2] 5e 90 [2] 51 8a [2] 4f 97 [2] 4d 96 [2] 56 90 [2] 4a 97 [2] 56 b8 }

  condition:
    any of them
}