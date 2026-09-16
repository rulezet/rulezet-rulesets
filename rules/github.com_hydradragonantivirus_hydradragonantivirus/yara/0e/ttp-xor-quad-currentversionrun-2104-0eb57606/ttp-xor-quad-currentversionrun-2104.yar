rule TTP_XOR_QUAD_CurrentVersionRun_2104 {
  strings:
    $key_2104 = { 72 6b [2] 56 65 [2] 7d 49 [2] 53 6b [2] 47 70 [2] 48 6a [2] 56 77 [2] 54 76 [2] 4f 70 [2] 53 77 [2] 4f 58 }

  condition:
    any of them
}