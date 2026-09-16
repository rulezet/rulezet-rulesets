rule TTP_XOR_QUAD_CurrentVersionRun_da10 {
  strings:
    $key_da10 = { 89 7f [2] ad 71 [2] 86 5d [2] a8 7f [2] bc 64 [2] b3 7e [2] ad 63 [2] af 62 [2] b4 64 [2] a8 63 [2] b4 4c }

  condition:
    any of them
}