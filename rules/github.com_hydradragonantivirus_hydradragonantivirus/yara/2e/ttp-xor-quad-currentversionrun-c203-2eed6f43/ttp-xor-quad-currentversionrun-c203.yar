rule TTP_XOR_QUAD_CurrentVersionRun_c203 {
  strings:
    $key_c203 = { 91 6c [2] b5 62 [2] 9e 4e [2] b0 6c [2] a4 77 [2] ab 6d [2] b5 70 [2] b7 71 [2] ac 77 [2] b0 70 [2] ac 5f }

  condition:
    any of them
}