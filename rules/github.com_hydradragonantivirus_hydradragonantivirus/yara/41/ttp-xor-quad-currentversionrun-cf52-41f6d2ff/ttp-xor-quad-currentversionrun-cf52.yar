rule TTP_XOR_QUAD_CurrentVersionRun_cf52 {
  strings:
    $key_cf52 = { 9c 3d [2] b8 33 [2] 93 1f [2] bd 3d [2] a9 26 [2] a6 3c [2] b8 21 [2] ba 20 [2] a1 26 [2] bd 21 [2] a1 0e }

  condition:
    any of them
}