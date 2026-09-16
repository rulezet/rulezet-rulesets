rule TTP_XOR_QUAD_CurrentVersionRun_c4f0 {
  strings:
    $key_c4f0 = { 97 9f [2] b3 91 [2] 98 bd [2] b6 9f [2] a2 84 [2] ad 9e [2] b3 83 [2] b1 82 [2] aa 84 [2] b6 83 [2] aa ac }

  condition:
    any of them
}