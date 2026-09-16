rule TTP_XOR_QUAD_CurrentVersionRun_db49 {
  strings:
    $key_db49 = { 88 26 [2] ac 28 [2] 87 04 [2] a9 26 [2] bd 3d [2] b2 27 [2] ac 3a [2] ae 3b [2] b5 3d [2] a9 3a [2] b5 15 }

  condition:
    any of them
}