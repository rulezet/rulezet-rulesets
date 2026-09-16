rule TTP_XOR_QUAD_CurrentVersionRun_c249 {
  strings:
    $key_c249 = { 91 26 [2] b5 28 [2] 9e 04 [2] b0 26 [2] a4 3d [2] ab 27 [2] b5 3a [2] b7 3b [2] ac 3d [2] b0 3a [2] ac 15 }

  condition:
    any of them
}