rule TTP_XOR_QUAD_CurrentVersionRun_d372 {
  strings:
    $key_d372 = { 80 1d [2] a4 13 [2] 8f 3f [2] a1 1d [2] b5 06 [2] ba 1c [2] a4 01 [2] a6 00 [2] bd 06 [2] a1 01 [2] bd 2e }

  condition:
    any of them
}