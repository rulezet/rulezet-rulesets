rule TTP_XOR_QUAD_CurrentVersionRun_dcf1 {
  strings:
    $key_dcf1 = { 8f 9e [2] ab 90 [2] 80 bc [2] ae 9e [2] ba 85 [2] b5 9f [2] ab 82 [2] a9 83 [2] b2 85 [2] ae 82 [2] b2 ad }

  condition:
    any of them
}