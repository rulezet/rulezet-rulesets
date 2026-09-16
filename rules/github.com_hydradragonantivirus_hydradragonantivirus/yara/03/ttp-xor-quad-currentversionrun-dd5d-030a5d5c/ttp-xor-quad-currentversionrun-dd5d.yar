rule TTP_XOR_QUAD_CurrentVersionRun_dd5d {
  strings:
    $key_dd5d = { 8e 32 [2] aa 3c [2] 81 10 [2] af 32 [2] bb 29 [2] b4 33 [2] aa 2e [2] a8 2f [2] b3 29 [2] af 2e [2] b3 01 }

  condition:
    any of them
}