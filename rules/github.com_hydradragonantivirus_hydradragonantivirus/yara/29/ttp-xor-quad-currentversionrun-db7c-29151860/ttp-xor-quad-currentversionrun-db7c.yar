rule TTP_XOR_QUAD_CurrentVersionRun_db7c {
  strings:
    $key_db7c = { 88 13 [2] ac 1d [2] 87 31 [2] a9 13 [2] bd 08 [2] b2 12 [2] ac 0f [2] ae 0e [2] b5 08 [2] a9 0f [2] b5 20 }

  condition:
    any of them
}