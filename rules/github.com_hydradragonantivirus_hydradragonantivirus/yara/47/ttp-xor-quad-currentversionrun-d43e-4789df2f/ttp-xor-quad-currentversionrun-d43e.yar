rule TTP_XOR_QUAD_CurrentVersionRun_d43e {
  strings:
    $key_d43e = { 87 51 [2] a3 5f [2] 88 73 [2] a6 51 [2] b2 4a [2] bd 50 [2] a3 4d [2] a1 4c [2] ba 4a [2] a6 4d [2] ba 62 }

  condition:
    any of them
}