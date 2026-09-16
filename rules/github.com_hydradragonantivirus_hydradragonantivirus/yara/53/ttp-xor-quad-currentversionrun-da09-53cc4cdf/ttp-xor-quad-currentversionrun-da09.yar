rule TTP_XOR_QUAD_CurrentVersionRun_da09 {
  strings:
    $key_da09 = { 89 66 [2] ad 68 [2] 86 44 [2] a8 66 [2] bc 7d [2] b3 67 [2] ad 7a [2] af 7b [2] b4 7d [2] a8 7a [2] b4 55 }

  condition:
    any of them
}