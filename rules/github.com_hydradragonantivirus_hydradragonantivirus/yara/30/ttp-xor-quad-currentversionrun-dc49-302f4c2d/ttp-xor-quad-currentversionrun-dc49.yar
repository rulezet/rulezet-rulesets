rule TTP_XOR_QUAD_CurrentVersionRun_dc49 {
  strings:
    $key_dc49 = { 8f 26 [2] ab 28 [2] 80 04 [2] ae 26 [2] ba 3d [2] b5 27 [2] ab 3a [2] a9 3b [2] b2 3d [2] ae 3a [2] b2 15 }

  condition:
    any of them
}