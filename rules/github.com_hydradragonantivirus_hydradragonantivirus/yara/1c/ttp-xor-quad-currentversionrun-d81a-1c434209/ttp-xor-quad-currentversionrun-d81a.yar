rule TTP_XOR_QUAD_CurrentVersionRun_d81a {
  strings:
    $key_d81a = { 8b 75 [2] af 7b [2] 84 57 [2] aa 75 [2] be 6e [2] b1 74 [2] af 69 [2] ad 68 [2] b6 6e [2] aa 69 [2] b6 46 }

  condition:
    any of them
}