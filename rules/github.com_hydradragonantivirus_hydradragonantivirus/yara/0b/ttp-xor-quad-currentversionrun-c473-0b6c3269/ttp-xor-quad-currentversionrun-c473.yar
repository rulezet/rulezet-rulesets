rule TTP_XOR_QUAD_CurrentVersionRun_c473 {
  strings:
    $key_c473 = { 97 1c [2] b3 12 [2] 98 3e [2] b6 1c [2] a2 07 [2] ad 1d [2] b3 00 [2] b1 01 [2] aa 07 [2] b6 00 [2] aa 2f }

  condition:
    any of them
}