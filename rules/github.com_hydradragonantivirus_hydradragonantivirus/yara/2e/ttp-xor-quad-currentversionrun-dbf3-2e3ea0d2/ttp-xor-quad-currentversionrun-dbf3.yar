rule TTP_XOR_QUAD_CurrentVersionRun_dbf3 {
  strings:
    $key_dbf3 = { 88 9c [2] ac 92 [2] 87 be [2] a9 9c [2] bd 87 [2] b2 9d [2] ac 80 [2] ae 81 [2] b5 87 [2] a9 80 [2] b5 af }

  condition:
    any of them
}