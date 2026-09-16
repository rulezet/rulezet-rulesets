rule TTP_XOR_QUAD_CurrentVersionRun_1759 {
  strings:
    $key_1759 = { 44 36 [2] 60 38 [2] 4b 14 [2] 65 36 [2] 71 2d [2] 7e 37 [2] 60 2a [2] 62 2b [2] 79 2d [2] 65 2a [2] 79 05 }

  condition:
    any of them
}