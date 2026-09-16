rule TTP_XOR_QUAD_CurrentVersionRun_cbe9 {
  strings:
    $key_cbe9 = { 98 86 [2] bc 88 [2] 97 a4 [2] b9 86 [2] ad 9d [2] a2 87 [2] bc 9a [2] be 9b [2] a5 9d [2] b9 9a [2] a5 b5 }

  condition:
    any of them
}