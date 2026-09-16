rule TTP_XOR_QUAD_CurrentVersionRun_dcec {
  strings:
    $key_dcec = { 8f 83 [2] ab 8d [2] 80 a1 [2] ae 83 [2] ba 98 [2] b5 82 [2] ab 9f [2] a9 9e [2] b2 98 [2] ae 9f [2] b2 b0 }

  condition:
    any of them
}