rule TTP_XOR_QUAD_CurrentVersionRun_3a6b {
  strings:
    $key_3a6b = { 69 04 [2] 4d 0a [2] 66 26 [2] 48 04 [2] 5c 1f [2] 53 05 [2] 4d 18 [2] 4f 19 [2] 54 1f [2] 48 18 [2] 54 37 }

  condition:
    any of them
}