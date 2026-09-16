rule TTP_XOR_QUAD_CurrentVersionRun_d800 {
  strings:
    $key_d800 = { 8b 6f [2] af 61 [2] 84 4d [2] aa 6f [2] be 74 [2] b1 6e [2] af 73 [2] ad 72 [2] b6 74 [2] aa 73 [2] b6 5c }

  condition:
    any of them
}