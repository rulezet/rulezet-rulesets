rule TTP_XOR_QUAD_CurrentVersionRun_de56 {
  strings:
    $key_de56 = { 8d 39 [2] a9 37 [2] 82 1b [2] ac 39 [2] b8 22 [2] b7 38 [2] a9 25 [2] ab 24 [2] b0 22 [2] ac 25 [2] b0 0a }

  condition:
    any of them
}