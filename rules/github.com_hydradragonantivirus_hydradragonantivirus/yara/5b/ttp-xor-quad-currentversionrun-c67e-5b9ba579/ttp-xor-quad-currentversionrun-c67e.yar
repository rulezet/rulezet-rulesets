rule TTP_XOR_QUAD_CurrentVersionRun_c67e {
  strings:
    $key_c67e = { 95 11 [2] b1 1f [2] 9a 33 [2] b4 11 [2] a0 0a [2] af 10 [2] b1 0d [2] b3 0c [2] a8 0a [2] b4 0d [2] a8 22 }

  condition:
    any of them
}