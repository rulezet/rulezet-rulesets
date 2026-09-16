rule TTP_XOR_QUAD_CurrentVersionRun_da32 {
  strings:
    $key_da32 = { 89 5d [2] ad 53 [2] 86 7f [2] a8 5d [2] bc 46 [2] b3 5c [2] ad 41 [2] af 40 [2] b4 46 [2] a8 41 [2] b4 6e }

  condition:
    any of them
}