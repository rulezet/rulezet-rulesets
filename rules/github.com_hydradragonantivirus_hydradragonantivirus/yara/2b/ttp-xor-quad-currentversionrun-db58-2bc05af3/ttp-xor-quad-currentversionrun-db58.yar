rule TTP_XOR_QUAD_CurrentVersionRun_db58 {
  strings:
    $key_db58 = { 88 37 [2] ac 39 [2] 87 15 [2] a9 37 [2] bd 2c [2] b2 36 [2] ac 2b [2] ae 2a [2] b5 2c [2] a9 2b [2] b5 04 }

  condition:
    any of them
}