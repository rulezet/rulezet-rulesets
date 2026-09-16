rule TTP_XOR_QUAD_CurrentVersionRun_db7f {
  strings:
    $key_db7f = { 88 10 [2] ac 1e [2] 87 32 [2] a9 10 [2] bd 0b [2] b2 11 [2] ac 0c [2] ae 0d [2] b5 0b [2] a9 0c [2] b5 23 }

  condition:
    any of them
}