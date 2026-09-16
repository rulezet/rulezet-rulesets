rule TTP_XOR_QUAD_CurrentVersionRun_db00 {
  strings:
    $key_db00 = { 88 6f [2] ac 61 [2] 87 4d [2] a9 6f [2] bd 74 [2] b2 6e [2] ac 73 [2] ae 72 [2] b5 74 [2] a9 73 [2] b5 5c }

  condition:
    any of them
}