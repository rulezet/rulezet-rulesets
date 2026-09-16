rule TTP_XOR_QUAD_CurrentVersionRun_d62e {
  strings:
    $key_d62e = { 85 41 [2] a1 4f [2] 8a 63 [2] a4 41 [2] b0 5a [2] bf 40 [2] a1 5d [2] a3 5c [2] b8 5a [2] a4 5d [2] b8 72 }

  condition:
    any of them
}