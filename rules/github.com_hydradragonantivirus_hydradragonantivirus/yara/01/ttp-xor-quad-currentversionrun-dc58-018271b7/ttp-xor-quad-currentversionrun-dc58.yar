rule TTP_XOR_QUAD_CurrentVersionRun_dc58 {
  strings:
    $key_dc58 = { 8f 37 [2] ab 39 [2] 80 15 [2] ae 37 [2] ba 2c [2] b5 36 [2] ab 2b [2] a9 2a [2] b2 2c [2] ae 2b [2] b2 04 }

  condition:
    any of them
}