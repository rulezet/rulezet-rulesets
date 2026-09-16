rule TTP_XOR_QUAD_CurrentVersionRun_6b55 {
  strings:
    $key_6b55 = { 38 3a [2] 1c 34 [2] 37 18 [2] 19 3a [2] 0d 21 [2] 02 3b [2] 1c 26 [2] 1e 27 [2] 05 21 [2] 19 26 [2] 05 09 }

  condition:
    any of them
}