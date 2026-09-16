rule TTP_XOR_QUAD_CurrentVersionRun_c230 {
  strings:
    $key_c230 = { 91 5f [2] b5 51 [2] 9e 7d [2] b0 5f [2] a4 44 [2] ab 5e [2] b5 43 [2] b7 42 [2] ac 44 [2] b0 43 [2] ac 6c }

  condition:
    any of them
}