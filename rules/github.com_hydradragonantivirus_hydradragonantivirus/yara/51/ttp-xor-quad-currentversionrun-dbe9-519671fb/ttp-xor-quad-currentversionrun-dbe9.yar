rule TTP_XOR_QUAD_CurrentVersionRun_dbe9 {
  strings:
    $key_dbe9 = { 88 86 [2] ac 88 [2] 87 a4 [2] a9 86 [2] bd 9d [2] b2 87 [2] ac 9a [2] ae 9b [2] b5 9d [2] a9 9a [2] b5 b5 }

  condition:
    any of them
}