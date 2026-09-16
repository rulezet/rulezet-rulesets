rule TTP_XOR_QUAD_CurrentVersionRun_de51 {
  strings:
    $key_de51 = { 8d 3e [2] a9 30 [2] 82 1c [2] ac 3e [2] b8 25 [2] b7 3f [2] a9 22 [2] ab 23 [2] b0 25 [2] ac 22 [2] b0 0d }

  condition:
    any of them
}