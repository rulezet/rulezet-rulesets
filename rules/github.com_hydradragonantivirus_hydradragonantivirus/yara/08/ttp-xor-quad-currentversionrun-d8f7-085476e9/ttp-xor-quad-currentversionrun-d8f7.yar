rule TTP_XOR_QUAD_CurrentVersionRun_d8f7 {
  strings:
    $key_d8f7 = { 8b 98 [2] af 96 [2] 84 ba [2] aa 98 [2] be 83 [2] b1 99 [2] af 84 [2] ad 85 [2] b6 83 [2] aa 84 [2] b6 ab }

  condition:
    any of them
}