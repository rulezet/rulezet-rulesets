rule TTP_XOR_QUAD_CurrentVersionRun_db2a {
  strings:
    $key_db2a = { 88 45 [2] ac 4b [2] 87 67 [2] a9 45 [2] bd 5e [2] b2 44 [2] ac 59 [2] ae 58 [2] b5 5e [2] a9 59 [2] b5 76 }

  condition:
    any of them
}