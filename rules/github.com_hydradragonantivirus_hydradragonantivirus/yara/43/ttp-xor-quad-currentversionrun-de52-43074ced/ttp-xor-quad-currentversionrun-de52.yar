rule TTP_XOR_QUAD_CurrentVersionRun_de52 {
  strings:
    $key_de52 = { 8d 3d [2] a9 33 [2] 82 1f [2] ac 3d [2] b8 26 [2] b7 3c [2] a9 21 [2] ab 20 [2] b0 26 [2] ac 21 [2] b0 0e }

  condition:
    any of them
}