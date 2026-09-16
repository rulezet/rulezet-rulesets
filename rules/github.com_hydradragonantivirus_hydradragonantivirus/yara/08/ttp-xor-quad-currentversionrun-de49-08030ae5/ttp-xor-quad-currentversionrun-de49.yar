rule TTP_XOR_QUAD_CurrentVersionRun_de49 {
  strings:
    $key_de49 = { 8d 26 [2] a9 28 [2] 82 04 [2] ac 26 [2] b8 3d [2] b7 27 [2] a9 3a [2] ab 3b [2] b0 3d [2] ac 3a [2] b0 15 }

  condition:
    any of them
}