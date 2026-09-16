rule TTP_XOR_QUAD_CurrentVersionRun_5156 {
  strings:
    $key_5156 = { 02 39 [2] 26 37 [2] 0d 1b [2] 23 39 [2] 37 22 [2] 38 38 [2] 26 25 [2] 24 24 [2] 3f 22 [2] 23 25 [2] 3f 0a }

  condition:
    any of them
}