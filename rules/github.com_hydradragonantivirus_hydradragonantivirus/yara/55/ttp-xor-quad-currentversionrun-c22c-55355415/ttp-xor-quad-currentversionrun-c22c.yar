rule TTP_XOR_QUAD_CurrentVersionRun_c22c {
  strings:
    $key_c22c = { 91 43 [2] b5 4d [2] 9e 61 [2] b0 43 [2] a4 58 [2] ab 42 [2] b5 5f [2] b7 5e [2] ac 58 [2] b0 5f [2] ac 70 }

  condition:
    any of them
}