rule TTP_XOR_QUAD_CurrentVersionRun_c6ee {
  strings:
    $key_c6ee = { 95 81 [2] b1 8f [2] 9a a3 [2] b4 81 [2] a0 9a [2] af 80 [2] b1 9d [2] b3 9c [2] a8 9a [2] b4 9d [2] a8 b2 }

  condition:
    any of them
}