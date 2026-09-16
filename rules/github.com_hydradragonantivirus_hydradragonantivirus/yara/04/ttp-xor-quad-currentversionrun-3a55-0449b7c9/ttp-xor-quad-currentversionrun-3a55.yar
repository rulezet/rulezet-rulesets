rule TTP_XOR_QUAD_CurrentVersionRun_3a55 {
  strings:
    $key_3a55 = { 69 3a [2] 4d 34 [2] 66 18 [2] 48 3a [2] 5c 21 [2] 53 3b [2] 4d 26 [2] 4f 27 [2] 54 21 [2] 48 26 [2] 54 09 }

  condition:
    any of them
}