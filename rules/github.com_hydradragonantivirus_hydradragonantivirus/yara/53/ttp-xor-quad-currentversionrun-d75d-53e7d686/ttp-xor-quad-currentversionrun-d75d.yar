rule TTP_XOR_QUAD_CurrentVersionRun_d75d {
  strings:
    $key_d75d = { 84 32 [2] a0 3c [2] 8b 10 [2] a5 32 [2] b1 29 [2] be 33 [2] a0 2e [2] a2 2f [2] b9 29 [2] a5 2e [2] b9 01 }

  condition:
    any of them
}