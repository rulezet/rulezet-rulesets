rule TTP_XOR_QUAD_CurrentVersionRun_d349 {
  strings:
    $key_d349 = { 80 26 [2] a4 28 [2] 8f 04 [2] a1 26 [2] b5 3d [2] ba 27 [2] a4 3a [2] a6 3b [2] bd 3d [2] a1 3a [2] bd 15 }

  condition:
    any of them
}