rule TTP_XOR_QUAD_CurrentVersionRun_512b {
  strings:
    $key_512b = { 02 44 [2] 26 4a [2] 0d 66 [2] 23 44 [2] 37 5f [2] 38 45 [2] 26 58 [2] 24 59 [2] 3f 5f [2] 23 58 [2] 3f 77 }

  condition:
    any of them
}