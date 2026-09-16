rule TTP_XOR_QUAD_CurrentVersionRun_d23b {
  strings:
    $key_d23b = { 81 54 [2] a5 5a [2] 8e 76 [2] a0 54 [2] b4 4f [2] bb 55 [2] a5 48 [2] a7 49 [2] bc 4f [2] a0 48 [2] bc 67 }

  condition:
    any of them
}