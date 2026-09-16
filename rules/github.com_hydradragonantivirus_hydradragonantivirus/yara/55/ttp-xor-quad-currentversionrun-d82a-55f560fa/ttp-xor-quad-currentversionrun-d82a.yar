rule TTP_XOR_QUAD_CurrentVersionRun_d82a {
  strings:
    $key_d82a = { 8b 45 [2] af 4b [2] 84 67 [2] aa 45 [2] be 5e [2] b1 44 [2] af 59 [2] ad 58 [2] b6 5e [2] aa 59 [2] b6 76 }

  condition:
    any of them
}