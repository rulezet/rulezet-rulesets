rule TTP_XOR_QUAD_CurrentVersionRun_db2d {
  strings:
    $key_db2d = { 88 42 [2] ac 4c [2] 87 60 [2] a9 42 [2] bd 59 [2] b2 43 [2] ac 5e [2] ae 5f [2] b5 59 [2] a9 5e [2] b5 71 }

  condition:
    any of them
}