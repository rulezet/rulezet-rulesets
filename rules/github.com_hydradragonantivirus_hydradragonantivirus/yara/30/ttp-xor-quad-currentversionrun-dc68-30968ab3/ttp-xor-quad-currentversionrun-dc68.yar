rule TTP_XOR_QUAD_CurrentVersionRun_dc68 {
  strings:
    $key_dc68 = { 8f 07 [2] ab 09 [2] 80 25 [2] ae 07 [2] ba 1c [2] b5 06 [2] ab 1b [2] a9 1a [2] b2 1c [2] ae 1b [2] b2 34 }

  condition:
    any of them
}