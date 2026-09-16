rule TTP_XOR_QUAD_CurrentVersionRun_d216 {
  strings:
    $key_d216 = { 81 79 [2] a5 77 [2] 8e 5b [2] a0 79 [2] b4 62 [2] bb 78 [2] a5 65 [2] a7 64 [2] bc 62 [2] a0 65 [2] bc 4a }

  condition:
    any of them
}