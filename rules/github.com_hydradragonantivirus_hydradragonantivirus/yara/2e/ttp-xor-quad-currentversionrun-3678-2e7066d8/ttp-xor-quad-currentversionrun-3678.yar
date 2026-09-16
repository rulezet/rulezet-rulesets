rule TTP_XOR_QUAD_CurrentVersionRun_3678 {
  strings:
    $key_3678 = { 65 17 [2] 41 19 [2] 6a 35 [2] 44 17 [2] 50 0c [2] 5f 16 [2] 41 0b [2] 43 0a [2] 58 0c [2] 44 0b [2] 58 24 }

  condition:
    any of them
}