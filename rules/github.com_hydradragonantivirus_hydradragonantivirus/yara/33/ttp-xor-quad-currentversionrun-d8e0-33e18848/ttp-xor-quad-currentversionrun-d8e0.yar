rule TTP_XOR_QUAD_CurrentVersionRun_d8e0 {
  strings:
    $key_d8e0 = { 8b 8f [2] af 81 [2] 84 ad [2] aa 8f [2] be 94 [2] b1 8e [2] af 93 [2] ad 92 [2] b6 94 [2] aa 93 [2] b6 bc }

  condition:
    any of them
}