rule TTP_XOR_QUAD_CurrentVersionRun_db7b {
  strings:
    $key_db7b = { 88 14 [2] ac 1a [2] 87 36 [2] a9 14 [2] bd 0f [2] b2 15 [2] ac 08 [2] ae 09 [2] b5 0f [2] a9 08 [2] b5 27 }

  condition:
    any of them
}