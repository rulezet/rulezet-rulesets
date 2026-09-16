rule TTP_XOR_QUAD_CurrentVersionRun_dc76 {
  strings:
    $key_dc76 = { 8f 19 [2] ab 17 [2] 80 3b [2] ae 19 [2] ba 02 [2] b5 18 [2] ab 05 [2] a9 04 [2] b2 02 [2] ae 05 [2] b2 2a }

  condition:
    any of them
}