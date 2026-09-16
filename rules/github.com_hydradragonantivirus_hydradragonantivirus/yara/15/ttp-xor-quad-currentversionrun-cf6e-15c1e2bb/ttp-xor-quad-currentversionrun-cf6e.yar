rule TTP_XOR_QUAD_CurrentVersionRun_cf6e {
  strings:
    $key_cf6e = { 9c 01 [2] b8 0f [2] 93 23 [2] bd 01 [2] a9 1a [2] a6 00 [2] b8 1d [2] ba 1c [2] a1 1a [2] bd 1d [2] a1 32 }

  condition:
    any of them
}