rule TTP_XOR_QUAD_CurrentVersionRun_e458 {
  strings:
    $key_e458 = { b7 37 [2] 93 39 [2] b8 15 [2] 96 37 [2] 82 2c [2] 8d 36 [2] 93 2b [2] 91 2a [2] 8a 2c [2] 96 2b [2] 8a 04 }

  condition:
    any of them
}