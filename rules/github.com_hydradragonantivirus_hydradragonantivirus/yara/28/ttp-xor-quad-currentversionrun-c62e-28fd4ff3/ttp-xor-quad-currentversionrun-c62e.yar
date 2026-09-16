rule TTP_XOR_QUAD_CurrentVersionRun_c62e {
  strings:
    $key_c62e = { 95 41 [2] b1 4f [2] 9a 63 [2] b4 41 [2] a0 5a [2] af 40 [2] b1 5d [2] b3 5c [2] a8 5a [2] b4 5d [2] a8 72 }

  condition:
    any of them
}