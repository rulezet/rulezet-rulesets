rule TTP_XOR_QUAD_CurrentVersionRun_c4e0 {
  strings:
    $key_c4e0 = { 97 8f [2] b3 81 [2] 98 ad [2] b6 8f [2] a2 94 [2] ad 8e [2] b3 93 [2] b1 92 [2] aa 94 [2] b6 93 [2] aa bc }

  condition:
    any of them
}