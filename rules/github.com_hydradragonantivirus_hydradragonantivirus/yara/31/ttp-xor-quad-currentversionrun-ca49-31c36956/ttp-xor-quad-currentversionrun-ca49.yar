rule TTP_XOR_QUAD_CurrentVersionRun_ca49 {
  strings:
    $key_ca49 = { 99 26 [2] bd 28 [2] 96 04 [2] b8 26 [2] ac 3d [2] a3 27 [2] bd 3a [2] bf 3b [2] a4 3d [2] b8 3a [2] a4 15 }

  condition:
    any of them
}