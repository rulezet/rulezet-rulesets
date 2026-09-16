rule TTP_XOR_QUAD_CurrentVersionRun_cef2 {
  strings:
    $key_cef2 = { 9d 9d [2] b9 93 [2] 92 bf [2] bc 9d [2] a8 86 [2] a7 9c [2] b9 81 [2] bb 80 [2] a0 86 [2] bc 81 [2] a0 ae }

  condition:
    any of them
}