rule TTP_XOR_QUAD_CurrentVersionRun_d87d {
  strings:
    $key_d87d = { 8b 12 [2] af 1c [2] 84 30 [2] aa 12 [2] be 09 [2] b1 13 [2] af 0e [2] ad 0f [2] b6 09 [2] aa 0e [2] b6 21 }

  condition:
    any of them
}