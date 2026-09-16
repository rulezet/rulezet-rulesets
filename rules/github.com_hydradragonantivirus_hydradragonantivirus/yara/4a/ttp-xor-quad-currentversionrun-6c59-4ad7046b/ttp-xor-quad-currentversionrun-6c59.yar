rule TTP_XOR_QUAD_CurrentVersionRun_6c59 {
  strings:
    $key_6c59 = { 3f 36 [2] 1b 38 [2] 30 14 [2] 1e 36 [2] 0a 2d [2] 05 37 [2] 1b 2a [2] 19 2b [2] 02 2d [2] 1e 2a [2] 02 05 }

  condition:
    any of them
}