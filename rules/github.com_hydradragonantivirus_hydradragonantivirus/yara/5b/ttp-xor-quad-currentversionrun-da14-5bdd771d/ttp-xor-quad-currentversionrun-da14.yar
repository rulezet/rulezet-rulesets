rule TTP_XOR_QUAD_CurrentVersionRun_da14 {
  strings:
    $key_da14 = { 89 7b [2] ad 75 [2] 86 59 [2] a8 7b [2] bc 60 [2] b3 7a [2] ad 67 [2] af 66 [2] b4 60 [2] a8 67 [2] b4 48 }

  condition:
    any of them
}