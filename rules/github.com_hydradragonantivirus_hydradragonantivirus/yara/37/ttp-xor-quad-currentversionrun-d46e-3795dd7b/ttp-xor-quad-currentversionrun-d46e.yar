rule TTP_XOR_QUAD_CurrentVersionRun_d46e {
  strings:
    $key_d46e = { 87 01 [2] a3 0f [2] 88 23 [2] a6 01 [2] b2 1a [2] bd 00 [2] a3 1d [2] a1 1c [2] ba 1a [2] a6 1d [2] ba 32 }

  condition:
    any of them
}