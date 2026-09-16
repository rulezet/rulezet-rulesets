rule TTP_XOR_QUAD_CurrentVersionRun_d74b {
  strings:
    $key_d74b = { 84 24 [2] a0 2a [2] 8b 06 [2] a5 24 [2] b1 3f [2] be 25 [2] a0 38 [2] a2 39 [2] b9 3f [2] a5 38 [2] b9 17 }

  condition:
    any of them
}