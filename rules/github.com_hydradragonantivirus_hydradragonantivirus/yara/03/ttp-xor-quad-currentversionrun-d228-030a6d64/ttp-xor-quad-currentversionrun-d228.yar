rule TTP_XOR_QUAD_CurrentVersionRun_d228 {
  strings:
    $key_d228 = { 81 47 [2] a5 49 [2] 8e 65 [2] a0 47 [2] b4 5c [2] bb 46 [2] a5 5b [2] a7 5a [2] bc 5c [2] a0 5b [2] bc 74 }

  condition:
    any of them
}