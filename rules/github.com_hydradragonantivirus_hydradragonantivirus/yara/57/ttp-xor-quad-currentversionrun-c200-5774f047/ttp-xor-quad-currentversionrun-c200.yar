rule TTP_XOR_QUAD_CurrentVersionRun_c200 {
  strings:
    $key_c200 = { 91 6f [2] b5 61 [2] 9e 4d [2] b0 6f [2] a4 74 [2] ab 6e [2] b5 73 [2] b7 72 [2] ac 74 [2] b0 73 [2] ac 5c }

  condition:
    any of them
}