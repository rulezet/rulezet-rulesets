rule TTP_XOR_QUAD_CurrentVersionRun_db50 {
  strings:
    $key_db50 = { 88 3f [2] ac 31 [2] 87 1d [2] a9 3f [2] bd 24 [2] b2 3e [2] ac 23 [2] ae 22 [2] b5 24 [2] a9 23 [2] b5 0c }

  condition:
    any of them
}