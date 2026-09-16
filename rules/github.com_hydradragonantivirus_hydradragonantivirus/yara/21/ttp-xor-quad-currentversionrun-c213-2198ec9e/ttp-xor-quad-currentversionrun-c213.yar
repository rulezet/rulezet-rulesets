rule TTP_XOR_QUAD_CurrentVersionRun_c213 {
  strings:
    $key_c213 = { 91 7c [2] b5 72 [2] 9e 5e [2] b0 7c [2] a4 67 [2] ab 7d [2] b5 60 [2] b7 61 [2] ac 67 [2] b0 60 [2] ac 4f }

  condition:
    any of them
}