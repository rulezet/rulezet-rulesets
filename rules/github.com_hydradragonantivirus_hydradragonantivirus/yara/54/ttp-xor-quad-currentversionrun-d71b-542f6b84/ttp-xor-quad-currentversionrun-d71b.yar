rule TTP_XOR_QUAD_CurrentVersionRun_d71b {
  strings:
    $key_d71b = { 84 74 [2] a0 7a [2] 8b 56 [2] a5 74 [2] b1 6f [2] be 75 [2] a0 68 [2] a2 69 [2] b9 6f [2] a5 68 [2] b9 47 }

  condition:
    any of them
}