rule TTP_XOR_QUAD_CurrentVersionRun_dc55 {
  strings:
    $key_dc55 = { 8f 3a [2] ab 34 [2] 80 18 [2] ae 3a [2] ba 21 [2] b5 3b [2] ab 26 [2] a9 27 [2] b2 21 [2] ae 26 [2] b2 09 }

  condition:
    any of them
}