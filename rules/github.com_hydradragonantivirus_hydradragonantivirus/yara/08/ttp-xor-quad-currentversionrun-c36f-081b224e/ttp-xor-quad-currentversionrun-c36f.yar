rule TTP_XOR_QUAD_CurrentVersionRun_c36f {
  strings:
    $key_c36f = { 90 00 [2] b4 0e [2] 9f 22 [2] b1 00 [2] a5 1b [2] aa 01 [2] b4 1c [2] b6 1d [2] ad 1b [2] b1 1c [2] ad 33 }

  condition:
    any of them
}