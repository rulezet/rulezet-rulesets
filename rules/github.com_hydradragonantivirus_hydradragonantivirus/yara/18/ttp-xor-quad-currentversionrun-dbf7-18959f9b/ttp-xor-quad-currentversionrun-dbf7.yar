rule TTP_XOR_QUAD_CurrentVersionRun_dbf7 {
  strings:
    $key_dbf7 = { 88 98 [2] ac 96 [2] 87 ba [2] a9 98 [2] bd 83 [2] b2 99 [2] ac 84 [2] ae 85 [2] b5 83 [2] a9 84 [2] b5 ab }

  condition:
    any of them
}