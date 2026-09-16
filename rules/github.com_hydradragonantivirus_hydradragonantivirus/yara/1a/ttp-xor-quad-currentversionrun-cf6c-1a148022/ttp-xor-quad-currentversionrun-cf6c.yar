rule TTP_XOR_QUAD_CurrentVersionRun_cf6c {
  strings:
    $key_cf6c = { 9c 03 [2] b8 0d [2] 93 21 [2] bd 03 [2] a9 18 [2] a6 02 [2] b8 1f [2] ba 1e [2] a1 18 [2] bd 1f [2] a1 30 }

  condition:
    any of them
}