rule TTP_XOR_QUAD_CurrentVersionRun_db59 {
  strings:
    $key_db59 = { 88 36 [2] ac 38 [2] 87 14 [2] a9 36 [2] bd 2d [2] b2 37 [2] ac 2a [2] ae 2b [2] b5 2d [2] a9 2a [2] b5 05 }

  condition:
    any of them
}