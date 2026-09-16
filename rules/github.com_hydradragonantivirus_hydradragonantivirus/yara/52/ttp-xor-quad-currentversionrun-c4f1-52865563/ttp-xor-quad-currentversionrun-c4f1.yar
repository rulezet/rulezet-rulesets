rule TTP_XOR_QUAD_CurrentVersionRun_c4f1 {
  strings:
    $key_c4f1 = { 97 9e [2] b3 90 [2] 98 bc [2] b6 9e [2] a2 85 [2] ad 9f [2] b3 82 [2] b1 83 [2] aa 85 [2] b6 82 [2] aa ad }

  condition:
    any of them
}