rule TTP_XOR_QUAD_CurrentVersionRun_4658 {
  strings:
    $key_4658 = { 15 37 [2] 31 39 [2] 1a 15 [2] 34 37 [2] 20 2c [2] 2f 36 [2] 31 2b [2] 33 2a [2] 28 2c [2] 34 2b [2] 28 04 }

  condition:
    any of them
}