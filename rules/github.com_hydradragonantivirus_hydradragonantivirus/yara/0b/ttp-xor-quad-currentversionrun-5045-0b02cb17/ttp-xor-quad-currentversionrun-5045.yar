rule TTP_XOR_QUAD_CurrentVersionRun_5045 {
  strings:
    $key_5045 = { 03 2a [2] 27 24 [2] 0c 08 [2] 22 2a [2] 36 31 [2] 39 2b [2] 27 36 [2] 25 37 [2] 3e 31 [2] 22 36 [2] 3e 19 }

  condition:
    any of them
}