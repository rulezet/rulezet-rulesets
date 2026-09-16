rule TTP_XOR_QUAD_CurrentVersionRun_d238 {
  strings:
    $key_d238 = { 81 57 [2] a5 59 [2] 8e 75 [2] a0 57 [2] b4 4c [2] bb 56 [2] a5 4b [2] a7 4a [2] bc 4c [2] a0 4b [2] bc 64 }

  condition:
    any of them
}