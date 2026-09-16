rule TTP_XOR_QUAD_CurrentVersionRun_db64 {
  strings:
    $key_db64 = { 88 0b [2] ac 05 [2] 87 29 [2] a9 0b [2] bd 10 [2] b2 0a [2] ac 17 [2] ae 16 [2] b5 10 [2] a9 17 [2] b5 38 }

  condition:
    any of them
}