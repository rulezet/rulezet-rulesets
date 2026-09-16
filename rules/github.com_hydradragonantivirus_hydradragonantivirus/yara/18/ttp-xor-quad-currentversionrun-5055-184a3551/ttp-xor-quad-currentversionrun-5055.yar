rule TTP_XOR_QUAD_CurrentVersionRun_5055 {
  strings:
    $key_5055 = { 03 3a [2] 27 34 [2] 0c 18 [2] 22 3a [2] 36 21 [2] 39 3b [2] 27 26 [2] 25 27 [2] 3e 21 [2] 22 26 [2] 3e 09 }

  condition:
    any of them
}