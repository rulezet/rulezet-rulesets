rule TTP_XOR_QUAD_CurrentVersionRun_dfea {
  strings:
    $key_dfea = { 8c 85 [2] a8 8b [2] 83 a7 [2] ad 85 [2] b9 9e [2] b6 84 [2] a8 99 [2] aa 98 [2] b1 9e [2] ad 99 [2] b1 b6 }

  condition:
    any of them
}