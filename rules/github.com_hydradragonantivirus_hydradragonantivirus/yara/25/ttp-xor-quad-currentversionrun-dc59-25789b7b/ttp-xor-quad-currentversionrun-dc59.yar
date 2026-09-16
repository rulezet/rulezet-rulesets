rule TTP_XOR_QUAD_CurrentVersionRun_dc59 {
  strings:
    $key_dc59 = { 8f 36 [2] ab 38 [2] 80 14 [2] ae 36 [2] ba 2d [2] b5 37 [2] ab 2a [2] a9 2b [2] b2 2d [2] ae 2a [2] b2 05 }

  condition:
    any of them
}