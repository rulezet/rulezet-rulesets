rule TTP_XOR_QUAD_CurrentVersionRun_da18 {
  strings:
    $key_da18 = { 89 77 [2] ad 79 [2] 86 55 [2] a8 77 [2] bc 6c [2] b3 76 [2] ad 6b [2] af 6a [2] b4 6c [2] a8 6b [2] b4 44 }

  condition:
    any of them
}