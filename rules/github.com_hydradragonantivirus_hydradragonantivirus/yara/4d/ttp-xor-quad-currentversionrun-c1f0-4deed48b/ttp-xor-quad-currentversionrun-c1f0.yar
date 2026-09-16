rule TTP_XOR_QUAD_CurrentVersionRun_c1f0 {
  strings:
    $key_c1f0 = { 92 9f [2] b6 91 [2] 9d bd [2] b3 9f [2] a7 84 [2] a8 9e [2] b6 83 [2] b4 82 [2] af 84 [2] b3 83 [2] af ac }

  condition:
    any of them
}