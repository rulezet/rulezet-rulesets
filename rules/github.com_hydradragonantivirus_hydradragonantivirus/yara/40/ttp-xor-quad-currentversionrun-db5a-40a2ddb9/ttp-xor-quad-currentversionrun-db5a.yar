rule TTP_XOR_QUAD_CurrentVersionRun_db5a {
  strings:
    $key_db5a = { 88 35 [2] ac 3b [2] 87 17 [2] a9 35 [2] bd 2e [2] b2 34 [2] ac 29 [2] ae 28 [2] b5 2e [2] a9 29 [2] b5 06 }

  condition:
    any of them
}