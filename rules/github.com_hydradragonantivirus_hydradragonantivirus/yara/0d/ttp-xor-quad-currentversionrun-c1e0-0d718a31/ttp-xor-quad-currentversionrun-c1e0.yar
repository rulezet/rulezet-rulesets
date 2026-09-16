rule TTP_XOR_QUAD_CurrentVersionRun_c1e0 {
  strings:
    $key_c1e0 = { 92 8f [2] b6 81 [2] 9d ad [2] b3 8f [2] a7 94 [2] a8 8e [2] b6 93 [2] b4 92 [2] af 94 [2] b3 93 [2] af bc }

  condition:
    any of them
}