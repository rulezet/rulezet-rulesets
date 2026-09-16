rule TTP_XOR_QUAD_CurrentVersionRun_dc67 {
  strings:
    $key_dc67 = { 8f 08 [2] ab 06 [2] 80 2a [2] ae 08 [2] ba 13 [2] b5 09 [2] ab 14 [2] a9 15 [2] b2 13 [2] ae 14 [2] b2 3b }

  condition:
    any of them
}