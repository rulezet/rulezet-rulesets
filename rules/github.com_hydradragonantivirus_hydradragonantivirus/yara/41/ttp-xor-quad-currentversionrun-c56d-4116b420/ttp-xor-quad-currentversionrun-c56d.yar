rule TTP_XOR_QUAD_CurrentVersionRun_c56d {
  strings:
    $key_c56d = { 96 02 [2] b2 0c [2] 99 20 [2] b7 02 [2] a3 19 [2] ac 03 [2] b2 1e [2] b0 1f [2] ab 19 [2] b7 1e [2] ab 31 }

  condition:
    any of them
}