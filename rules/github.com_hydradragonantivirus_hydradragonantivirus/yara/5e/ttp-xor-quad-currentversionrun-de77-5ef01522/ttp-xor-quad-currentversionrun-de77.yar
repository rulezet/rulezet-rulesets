rule TTP_XOR_QUAD_CurrentVersionRun_de77 {
  strings:
    $key_de77 = { 8d 18 [2] a9 16 [2] 82 3a [2] ac 18 [2] b8 03 [2] b7 19 [2] a9 04 [2] ab 05 [2] b0 03 [2] ac 04 [2] b0 2b }

  condition:
    any of them
}