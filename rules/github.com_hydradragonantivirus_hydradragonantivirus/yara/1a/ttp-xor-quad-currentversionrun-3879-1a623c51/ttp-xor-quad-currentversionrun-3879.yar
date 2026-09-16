rule TTP_XOR_QUAD_CurrentVersionRun_3879 {
  strings:
    $key_3879 = { 6b 16 [2] 4f 18 [2] 64 34 [2] 4a 16 [2] 5e 0d [2] 51 17 [2] 4f 0a [2] 4d 0b [2] 56 0d [2] 4a 0a [2] 56 25 }

  condition:
    any of them
}