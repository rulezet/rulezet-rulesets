rule TTP_XOR_QUAD_CurrentVersionRun_c500 {
  strings:
    $key_c500 = { 96 6f [2] b2 61 [2] 99 4d [2] b7 6f [2] a3 74 [2] ac 6e [2] b2 73 [2] b0 72 [2] ab 74 [2] b7 73 [2] ab 5c }

  condition:
    any of them
}