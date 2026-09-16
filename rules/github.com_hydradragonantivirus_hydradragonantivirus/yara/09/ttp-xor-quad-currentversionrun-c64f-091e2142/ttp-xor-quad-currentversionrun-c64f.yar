rule TTP_XOR_QUAD_CurrentVersionRun_c64f {
  strings:
    $key_c64f = { 95 20 [2] b1 2e [2] 9a 02 [2] b4 20 [2] a0 3b [2] af 21 [2] b1 3c [2] b3 3d [2] a8 3b [2] b4 3c [2] a8 13 }

  condition:
    any of them
}