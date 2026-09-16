rule TTP_XOR_QUAD_CurrentVersionRun_d8d2 {
  strings:
    $key_d8d2 = { 8b bd [2] af b3 [2] 84 9f [2] aa bd [2] be a6 [2] b1 bc [2] af a1 [2] ad a0 [2] b6 a6 [2] aa a1 [2] b6 8e }

  condition:
    any of them
}