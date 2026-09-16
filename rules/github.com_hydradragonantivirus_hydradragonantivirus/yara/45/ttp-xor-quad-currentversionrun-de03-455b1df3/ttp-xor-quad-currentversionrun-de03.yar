rule TTP_XOR_QUAD_CurrentVersionRun_de03 {
  strings:
    $key_de03 = { 8d 6c [2] a9 62 [2] 82 4e [2] ac 6c [2] b8 77 [2] b7 6d [2] a9 70 [2] ab 71 [2] b0 77 [2] ac 70 [2] b0 5f }

  condition:
    any of them
}