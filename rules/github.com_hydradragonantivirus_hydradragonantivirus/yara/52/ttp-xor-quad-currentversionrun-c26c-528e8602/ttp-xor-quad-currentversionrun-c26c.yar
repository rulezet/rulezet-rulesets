rule TTP_XOR_QUAD_CurrentVersionRun_c26c {
  strings:
    $key_c26c = { 91 03 [2] b5 0d [2] 9e 21 [2] b0 03 [2] a4 18 [2] ab 02 [2] b5 1f [2] b7 1e [2] ac 18 [2] b0 1f [2] ac 30 }

  condition:
    any of them
}