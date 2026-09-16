rule TTP_XOR_QUAD_CurrentVersionRun_d823 {
  strings:
    $key_d823 = { 8b 4c [2] af 42 [2] 84 6e [2] aa 4c [2] be 57 [2] b1 4d [2] af 50 [2] ad 51 [2] b6 57 [2] aa 50 [2] b6 7f }

  condition:
    any of them
}