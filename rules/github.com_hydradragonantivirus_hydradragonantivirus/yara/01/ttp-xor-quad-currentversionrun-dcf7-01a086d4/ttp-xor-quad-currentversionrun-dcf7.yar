rule TTP_XOR_QUAD_CurrentVersionRun_dcf7 {
  strings:
    $key_dcf7 = { 8f 98 [2] ab 96 [2] 80 ba [2] ae 98 [2] ba 83 [2] b5 99 [2] ab 84 [2] a9 85 [2] b2 83 [2] ae 84 [2] b2 ab }

  condition:
    any of them
}