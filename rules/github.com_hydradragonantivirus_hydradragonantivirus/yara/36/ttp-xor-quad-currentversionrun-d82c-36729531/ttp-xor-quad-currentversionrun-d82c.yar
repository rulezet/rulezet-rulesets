rule TTP_XOR_QUAD_CurrentVersionRun_d82c {
  strings:
    $key_d82c = { 8b 43 [2] af 4d [2] 84 61 [2] aa 43 [2] be 58 [2] b1 42 [2] af 5f [2] ad 5e [2] b6 58 [2] aa 5f [2] b6 70 }

  condition:
    any of them
}