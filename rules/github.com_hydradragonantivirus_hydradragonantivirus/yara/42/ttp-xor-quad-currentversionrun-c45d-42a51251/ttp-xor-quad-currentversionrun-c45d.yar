rule TTP_XOR_QUAD_CurrentVersionRun_c45d {
  strings:
    $key_c45d = { 97 32 [2] b3 3c [2] 98 10 [2] b6 32 [2] a2 29 [2] ad 33 [2] b3 2e [2] b1 2f [2] aa 29 [2] b6 2e [2] aa 01 }

  condition:
    any of them
}