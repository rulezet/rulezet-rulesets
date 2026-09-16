rule TTP_XOR_QUAD_CurrentVersionRun_d05d {
  strings:
    $key_d05d = { 83 32 [2] a7 3c [2] 8c 10 [2] a2 32 [2] b6 29 [2] b9 33 [2] a7 2e [2] a5 2f [2] be 29 [2] a2 2e [2] be 01 }

  condition:
    any of them
}