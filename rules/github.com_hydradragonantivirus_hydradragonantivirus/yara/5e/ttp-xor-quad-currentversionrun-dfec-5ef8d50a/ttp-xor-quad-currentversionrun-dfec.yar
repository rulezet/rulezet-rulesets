rule TTP_XOR_QUAD_CurrentVersionRun_dfec {
  strings:
    $key_dfec = { 8c 83 [2] a8 8d [2] 83 a1 [2] ad 83 [2] b9 98 [2] b6 82 [2] a8 9f [2] aa 9e [2] b1 98 [2] ad 9f [2] b1 b0 }

  condition:
    any of them
}