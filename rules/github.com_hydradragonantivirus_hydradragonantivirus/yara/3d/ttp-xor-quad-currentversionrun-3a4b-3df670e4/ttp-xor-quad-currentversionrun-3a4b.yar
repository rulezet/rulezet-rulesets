rule TTP_XOR_QUAD_CurrentVersionRun_3a4b {
  strings:
    $key_3a4b = { 69 24 [2] 4d 2a [2] 66 06 [2] 48 24 [2] 5c 3f [2] 53 25 [2] 4d 38 [2] 4f 39 [2] 54 3f [2] 48 38 [2] 54 17 }

  condition:
    any of them
}