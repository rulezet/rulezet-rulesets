rule TTP_XOR_QUAD_CurrentVersionRun_dc48 {
  strings:
    $key_dc48 = { 8f 27 [2] ab 29 [2] 80 05 [2] ae 27 [2] ba 3c [2] b5 26 [2] ab 3b [2] a9 3a [2] b2 3c [2] ae 3b [2] b2 14 }

  condition:
    any of them
}