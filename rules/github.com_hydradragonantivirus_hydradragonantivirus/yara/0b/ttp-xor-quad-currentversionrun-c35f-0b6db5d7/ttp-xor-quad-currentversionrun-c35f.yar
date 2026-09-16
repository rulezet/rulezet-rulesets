rule TTP_XOR_QUAD_CurrentVersionRun_c35f {
  strings:
    $key_c35f = { 90 30 [2] b4 3e [2] 9f 12 [2] b1 30 [2] a5 2b [2] aa 31 [2] b4 2c [2] b6 2d [2] ad 2b [2] b1 2c [2] ad 03 }

  condition:
    any of them
}