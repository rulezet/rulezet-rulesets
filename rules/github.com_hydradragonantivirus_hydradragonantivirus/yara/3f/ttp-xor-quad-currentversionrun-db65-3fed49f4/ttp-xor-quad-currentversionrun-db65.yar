rule TTP_XOR_QUAD_CurrentVersionRun_db65 {
  strings:
    $key_db65 = { 88 0a [2] ac 04 [2] 87 28 [2] a9 0a [2] bd 11 [2] b2 0b [2] ac 16 [2] ae 17 [2] b5 11 [2] a9 16 [2] b5 39 }

  condition:
    any of them
}