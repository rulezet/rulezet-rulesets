rule TTP_XOR_QUAD_CurrentVersionRun_db5b {
  strings:
    $key_db5b = { 88 34 [2] ac 3a [2] 87 16 [2] a9 34 [2] bd 2f [2] b2 35 [2] ac 28 [2] ae 29 [2] b5 2f [2] a9 28 [2] b5 07 }

  condition:
    any of them
}