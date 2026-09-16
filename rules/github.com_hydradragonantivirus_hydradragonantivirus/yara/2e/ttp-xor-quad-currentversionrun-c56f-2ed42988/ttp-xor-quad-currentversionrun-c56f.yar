rule TTP_XOR_QUAD_CurrentVersionRun_c56f {
  strings:
    $key_c56f = { 96 00 [2] b2 0e [2] 99 22 [2] b7 00 [2] a3 1b [2] ac 01 [2] b2 1c [2] b0 1d [2] ab 1b [2] b7 1c [2] ab 33 }

  condition:
    any of them
}