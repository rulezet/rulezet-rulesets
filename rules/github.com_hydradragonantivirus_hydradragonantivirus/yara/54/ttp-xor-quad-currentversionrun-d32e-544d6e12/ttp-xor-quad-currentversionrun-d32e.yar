rule TTP_XOR_QUAD_CurrentVersionRun_d32e {
  strings:
    $key_d32e = { 80 41 [2] a4 4f [2] 8f 63 [2] a1 41 [2] b5 5a [2] ba 40 [2] a4 5d [2] a6 5c [2] bd 5a [2] a1 5d [2] bd 72 }

  condition:
    any of them
}