rule TTP_XOR_QUAD_CurrentVersionRun_c6f0 {
  strings:
    $key_c6f0 = { 95 9f [2] b1 91 [2] 9a bd [2] b4 9f [2] a0 84 [2] af 9e [2] b1 83 [2] b3 82 [2] a8 84 [2] b4 83 [2] a8 ac }

  condition:
    any of them
}