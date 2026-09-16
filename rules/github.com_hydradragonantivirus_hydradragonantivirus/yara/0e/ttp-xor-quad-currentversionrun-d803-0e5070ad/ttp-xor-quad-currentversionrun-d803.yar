rule TTP_XOR_QUAD_CurrentVersionRun_d803 {
  strings:
    $key_d803 = { 8b 6c [2] af 62 [2] 84 4e [2] aa 6c [2] be 77 [2] b1 6d [2] af 70 [2] ad 71 [2] b6 77 [2] aa 70 [2] b6 5f }

  condition:
    any of them
}