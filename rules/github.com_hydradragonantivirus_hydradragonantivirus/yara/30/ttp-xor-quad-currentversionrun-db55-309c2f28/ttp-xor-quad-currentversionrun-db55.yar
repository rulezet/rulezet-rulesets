rule TTP_XOR_QUAD_CurrentVersionRun_db55 {
  strings:
    $key_db55 = { 88 3a [2] ac 34 [2] 87 18 [2] a9 3a [2] bd 21 [2] b2 3b [2] ac 26 [2] ae 27 [2] b5 21 [2] a9 26 [2] b5 09 }

  condition:
    any of them
}