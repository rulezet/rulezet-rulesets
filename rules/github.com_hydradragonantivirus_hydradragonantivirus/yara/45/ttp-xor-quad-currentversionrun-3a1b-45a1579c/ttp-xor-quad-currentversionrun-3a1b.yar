rule TTP_XOR_QUAD_CurrentVersionRun_3a1b {
  strings:
    $key_3a1b = { 69 74 [2] 4d 7a [2] 66 56 [2] 48 74 [2] 5c 6f [2] 53 75 [2] 4d 68 [2] 4f 69 [2] 54 6f [2] 48 68 [2] 54 47 }

  condition:
    any of them
}