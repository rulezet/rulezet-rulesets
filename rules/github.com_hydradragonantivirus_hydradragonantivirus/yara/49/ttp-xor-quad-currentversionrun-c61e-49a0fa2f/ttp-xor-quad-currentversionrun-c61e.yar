rule TTP_XOR_QUAD_CurrentVersionRun_c61e {
  strings:
    $key_c61e = { 95 71 [2] b1 7f [2] 9a 53 [2] b4 71 [2] a0 6a [2] af 70 [2] b1 6d [2] b3 6c [2] a8 6a [2] b4 6d [2] a8 42 }

  condition:
    any of them
}