rule TTP_XOR_QUAD_CurrentVersionRun_dc44 {
  strings:
    $key_dc44 = { 8f 2b [2] ab 25 [2] 80 09 [2] ae 2b [2] ba 30 [2] b5 2a [2] ab 37 [2] a9 36 [2] b2 30 [2] ae 37 [2] b2 18 }

  condition:
    any of them
}