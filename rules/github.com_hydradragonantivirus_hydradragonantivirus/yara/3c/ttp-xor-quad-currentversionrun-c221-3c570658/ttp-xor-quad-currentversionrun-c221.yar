rule TTP_XOR_QUAD_CurrentVersionRun_c221 {
  strings:
    $key_c221 = { 91 4e [2] b5 40 [2] 9e 6c [2] b0 4e [2] a4 55 [2] ab 4f [2] b5 52 [2] b7 53 [2] ac 55 [2] b0 52 [2] ac 7d }

  condition:
    any of them
}