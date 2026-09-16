rule TTP_XOR_QUAD_CurrentVersionRun_d863 {
  strings:
    $key_d863 = { 8b 0c [2] af 02 [2] 84 2e [2] aa 0c [2] be 17 [2] b1 0d [2] af 10 [2] ad 11 [2] b6 17 [2] aa 10 [2] b6 3f }

  condition:
    any of them
}