rule TTP_XOR_QUAD_CurrentVersionRun_dbe8 {
  strings:
    $key_dbe8 = { 88 87 [2] ac 89 [2] 87 a5 [2] a9 87 [2] bd 9c [2] b2 86 [2] ac 9b [2] ae 9a [2] b5 9c [2] a9 9b [2] b5 b4 }

  condition:
    any of them
}