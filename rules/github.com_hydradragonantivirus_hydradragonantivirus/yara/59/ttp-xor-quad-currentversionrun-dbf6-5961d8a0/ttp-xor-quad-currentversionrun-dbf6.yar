rule TTP_XOR_QUAD_CurrentVersionRun_dbf6 {
  strings:
    $key_dbf6 = { 88 99 [2] ac 97 [2] 87 bb [2] a9 99 [2] bd 82 [2] b2 98 [2] ac 85 [2] ae 84 [2] b5 82 [2] a9 85 [2] b5 aa }

  condition:
    any of them
}