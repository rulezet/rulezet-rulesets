rule TTP_XOR_QUAD_CurrentVersionRun_dc56 {
  strings:
    $key_dc56 = { 8f 39 [2] ab 37 [2] 80 1b [2] ae 39 [2] ba 22 [2] b5 38 [2] ab 25 [2] a9 24 [2] b2 22 [2] ae 25 [2] b2 0a }

  condition:
    any of them
}