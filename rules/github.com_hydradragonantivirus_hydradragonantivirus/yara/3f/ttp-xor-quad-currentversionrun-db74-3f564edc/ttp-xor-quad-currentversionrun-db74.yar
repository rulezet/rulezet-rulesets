rule TTP_XOR_QUAD_CurrentVersionRun_db74 {
  strings:
    $key_db74 = { 88 1b [2] ac 15 [2] 87 39 [2] a9 1b [2] bd 00 [2] b2 1a [2] ac 07 [2] ae 06 [2] b5 00 [2] a9 07 [2] b5 28 }

  condition:
    any of them
}