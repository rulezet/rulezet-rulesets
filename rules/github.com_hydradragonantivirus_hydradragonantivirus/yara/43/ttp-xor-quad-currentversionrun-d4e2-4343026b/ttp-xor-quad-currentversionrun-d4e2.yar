rule TTP_XOR_QUAD_CurrentVersionRun_d4e2 {
  strings:
    $key_d4e2 = { 87 8d [2] a3 83 [2] 88 af [2] a6 8d [2] b2 96 [2] bd 8c [2] a3 91 [2] a1 90 [2] ba 96 [2] a6 91 [2] ba be }

  condition:
    any of them
}