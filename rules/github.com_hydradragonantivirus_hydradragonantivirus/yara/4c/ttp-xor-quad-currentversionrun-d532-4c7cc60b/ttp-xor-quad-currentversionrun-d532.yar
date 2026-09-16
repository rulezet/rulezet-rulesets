rule TTP_XOR_QUAD_CurrentVersionRun_d532 {
  strings:
    $key_d532 = { 86 5d [2] a2 53 [2] 89 7f [2] a7 5d [2] b3 46 [2] bc 5c [2] a2 41 [2] a0 40 [2] bb 46 [2] a7 41 [2] bb 6e }

  condition:
    any of them
}