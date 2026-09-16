rule TTP_XOR_QUAD_CurrentVersionRun_db24 {
  strings:
    $key_db24 = { 88 4b [2] ac 45 [2] 87 69 [2] a9 4b [2] bd 50 [2] b2 4a [2] ac 57 [2] ae 56 [2] b5 50 [2] a9 57 [2] b5 78 }

  condition:
    any of them
}