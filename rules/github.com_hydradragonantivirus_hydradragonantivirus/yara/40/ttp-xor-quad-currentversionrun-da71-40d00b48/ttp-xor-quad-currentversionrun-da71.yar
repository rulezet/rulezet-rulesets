rule TTP_XOR_QUAD_CurrentVersionRun_da71 {
  strings:
    $key_da71 = { 89 1e [2] ad 10 [2] 86 3c [2] a8 1e [2] bc 05 [2] b3 1f [2] ad 02 [2] af 03 [2] b4 05 [2] a8 02 [2] b4 2d }

  condition:
    any of them
}