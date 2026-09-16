rule TTP_XOR_QUAD_CurrentVersionRun_d6fe {
  strings:
    $key_d6fe = { 85 91 [2] a1 9f [2] 8a b3 [2] a4 91 [2] b0 8a [2] bf 90 [2] a1 8d [2] a3 8c [2] b8 8a [2] a4 8d [2] b8 a2 }

  condition:
    any of them
}