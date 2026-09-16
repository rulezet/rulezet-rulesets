rule TTP_XOR_QUAD_CurrentVersionRun_cf2e {
  strings:
    $key_cf2e = { 9c 41 [2] b8 4f [2] 93 63 [2] bd 41 [2] a9 5a [2] a6 40 [2] b8 5d [2] ba 5c [2] a1 5a [2] bd 5d [2] a1 72 }

  condition:
    any of them
}