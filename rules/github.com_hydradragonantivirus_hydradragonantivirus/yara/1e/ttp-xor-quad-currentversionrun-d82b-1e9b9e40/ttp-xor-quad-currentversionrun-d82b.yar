rule TTP_XOR_QUAD_CurrentVersionRun_d82b {
  strings:
    $key_d82b = { 8b 44 [2] af 4a [2] 84 66 [2] aa 44 [2] be 5f [2] b1 45 [2] af 58 [2] ad 59 [2] b6 5f [2] aa 58 [2] b6 77 }

  condition:
    any of them
}