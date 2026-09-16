rule TTP_XOR_QUAD_CurrentVersionRun_d85d {
  strings:
    $key_d85d = { 8b 32 [2] af 3c [2] 84 10 [2] aa 32 [2] be 29 [2] b1 33 [2] af 2e [2] ad 2f [2] b6 29 [2] aa 2e [2] b6 01 }

  condition:
    any of them
}