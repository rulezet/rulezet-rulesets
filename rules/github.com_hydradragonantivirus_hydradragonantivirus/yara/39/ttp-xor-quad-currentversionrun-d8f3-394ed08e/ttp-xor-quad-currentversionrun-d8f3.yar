rule TTP_XOR_QUAD_CurrentVersionRun_d8f3 {
  strings:
    $key_d8f3 = { 8b 9c [2] af 92 [2] 84 be [2] aa 9c [2] be 87 [2] b1 9d [2] af 80 [2] ad 81 [2] b6 87 [2] aa 80 [2] b6 af }

  condition:
    any of them
}