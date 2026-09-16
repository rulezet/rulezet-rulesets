rule TTP_XOR_QUAD_CurrentVersionRun_d836 {
  strings:
    $key_d836 = { 8b 59 [2] af 57 [2] 84 7b [2] aa 59 [2] be 42 [2] b1 58 [2] af 45 [2] ad 44 [2] b6 42 [2] aa 45 [2] b6 6a }

  condition:
    any of them
}