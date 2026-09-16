rule TTP_XOR_QUAD_CurrentVersionRun_c65f {
  strings:
    $key_c65f = { 95 30 [2] b1 3e [2] 9a 12 [2] b4 30 [2] a0 2b [2] af 31 [2] b1 2c [2] b3 2d [2] a8 2b [2] b4 2c [2] a8 03 }

  condition:
    any of them
}