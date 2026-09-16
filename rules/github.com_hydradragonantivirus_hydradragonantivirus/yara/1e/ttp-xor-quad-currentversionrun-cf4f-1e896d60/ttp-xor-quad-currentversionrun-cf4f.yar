rule TTP_XOR_QUAD_CurrentVersionRun_cf4f {
  strings:
    $key_cf4f = { 9c 20 [2] b8 2e [2] 93 02 [2] bd 20 [2] a9 3b [2] a6 21 [2] b8 3c [2] ba 3d [2] a1 3b [2] bd 3c [2] a1 13 }

  condition:
    any of them
}