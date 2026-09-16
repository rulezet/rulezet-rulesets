rule TTP_XOR_QUAD_CurrentVersionRun_dafe {
  strings:
    $key_dafe = { 89 91 [2] ad 9f [2] 86 b3 [2] a8 91 [2] bc 8a [2] b3 90 [2] ad 8d [2] af 8c [2] b4 8a [2] a8 8d [2] b4 a2 }

  condition:
    any of them
}