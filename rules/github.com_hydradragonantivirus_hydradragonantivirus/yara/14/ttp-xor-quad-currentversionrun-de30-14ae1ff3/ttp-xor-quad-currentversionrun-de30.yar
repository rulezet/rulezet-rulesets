rule TTP_XOR_QUAD_CurrentVersionRun_de30 {
  strings:
    $key_de30 = { 8d 5f [2] a9 51 [2] 82 7d [2] ac 5f [2] b8 44 [2] b7 5e [2] a9 43 [2] ab 42 [2] b0 44 [2] ac 43 [2] b0 6c }

  condition:
    any of them
}