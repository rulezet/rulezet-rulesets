rule TTP_XOR_QUAD_CurrentVersionRun_dbf4 {
  strings:
    $key_dbf4 = { 88 9b [2] ac 95 [2] 87 b9 [2] a9 9b [2] bd 80 [2] b2 9a [2] ac 87 [2] ae 86 [2] b5 80 [2] a9 87 [2] b5 a8 }

  condition:
    any of them
}