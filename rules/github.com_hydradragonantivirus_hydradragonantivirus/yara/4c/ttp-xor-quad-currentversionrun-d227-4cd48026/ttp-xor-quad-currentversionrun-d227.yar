rule TTP_XOR_QUAD_CurrentVersionRun_d227 {
  strings:
    $key_d227 = { 81 48 [2] a5 46 [2] 8e 6a [2] a0 48 [2] b4 53 [2] bb 49 [2] a5 54 [2] a7 55 [2] bc 53 [2] a0 54 [2] bc 7b }

  condition:
    any of them
}