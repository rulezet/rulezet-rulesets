rule TTP_XOR_QUAD_CurrentVersionRun_dc66 {
  strings:
    $key_dc66 = { 8f 09 [2] ab 07 [2] 80 2b [2] ae 09 [2] ba 12 [2] b5 08 [2] ab 15 [2] a9 14 [2] b2 12 [2] ae 15 [2] b2 3a }

  condition:
    any of them
}