rule TTP_XOR_QUAD_CurrentVersionRun_c503 {
  strings:
    $key_c503 = { 96 6c [2] b2 62 [2] 99 4e [2] b7 6c [2] a3 77 [2] ac 6d [2] b2 70 [2] b0 71 [2] ab 77 [2] b7 70 [2] ab 5f }

  condition:
    any of them
}