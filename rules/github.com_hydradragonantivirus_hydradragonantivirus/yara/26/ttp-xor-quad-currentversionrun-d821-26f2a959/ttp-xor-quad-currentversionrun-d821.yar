rule TTP_XOR_QUAD_CurrentVersionRun_d821 {
  strings:
    $key_d821 = { 8b 4e [2] af 40 [2] 84 6c [2] aa 4e [2] be 55 [2] b1 4f [2] af 52 [2] ad 53 [2] b6 55 [2] aa 52 [2] b6 7d }

  condition:
    any of them
}