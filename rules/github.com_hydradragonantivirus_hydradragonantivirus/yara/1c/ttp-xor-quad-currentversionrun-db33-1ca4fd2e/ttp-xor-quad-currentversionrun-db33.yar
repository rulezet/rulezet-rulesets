rule TTP_XOR_QUAD_CurrentVersionRun_db33 {
  strings:
    $key_db33 = { 88 5c [2] ac 52 [2] 87 7e [2] a9 5c [2] bd 47 [2] b2 5d [2] ac 40 [2] ae 41 [2] b5 47 [2] a9 40 [2] b5 6f }

  condition:
    any of them
}