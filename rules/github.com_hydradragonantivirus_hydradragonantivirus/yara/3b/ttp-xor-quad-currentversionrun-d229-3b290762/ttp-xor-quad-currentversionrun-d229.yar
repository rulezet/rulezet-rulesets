rule TTP_XOR_QUAD_CurrentVersionRun_d229 {
  strings:
    $key_d229 = { 81 46 [2] a5 48 [2] 8e 64 [2] a0 46 [2] b4 5d [2] bb 47 [2] a5 5a [2] a7 5b [2] bc 5d [2] a0 5a [2] bc 75 }

  condition:
    any of them
}