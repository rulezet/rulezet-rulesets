rule TTP_XOR_QUAD_CurrentVersionRun_d458 {
  strings:
    $key_d458 = { 87 37 [2] a3 39 [2] 88 15 [2] a6 37 [2] b2 2c [2] bd 36 [2] a3 2b [2] a1 2a [2] ba 2c [2] a6 2b [2] ba 04 }

  condition:
    any of them
}