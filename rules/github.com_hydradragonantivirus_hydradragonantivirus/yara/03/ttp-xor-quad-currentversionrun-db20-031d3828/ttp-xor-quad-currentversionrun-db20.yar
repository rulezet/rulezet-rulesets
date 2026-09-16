rule TTP_XOR_QUAD_CurrentVersionRun_db20 {
  strings:
    $key_db20 = { 88 4f [2] ac 41 [2] 87 6d [2] a9 4f [2] bd 54 [2] b2 4e [2] ac 53 [2] ae 52 [2] b5 54 [2] a9 53 [2] b5 7c }

  condition:
    any of them
}