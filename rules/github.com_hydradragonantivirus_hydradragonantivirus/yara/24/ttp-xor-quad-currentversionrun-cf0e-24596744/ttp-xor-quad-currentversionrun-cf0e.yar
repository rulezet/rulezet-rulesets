rule TTP_XOR_QUAD_CurrentVersionRun_cf0e {
  strings:
    $key_cf0e = { 9c 61 [2] b8 6f [2] 93 43 [2] bd 61 [2] a9 7a [2] a6 60 [2] b8 7d [2] ba 7c [2] a1 7a [2] bd 7d [2] a1 52 }

  condition:
    any of them
}