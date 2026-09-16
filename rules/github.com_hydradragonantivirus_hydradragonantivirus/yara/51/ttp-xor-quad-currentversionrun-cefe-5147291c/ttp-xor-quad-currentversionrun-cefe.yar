rule TTP_XOR_QUAD_CurrentVersionRun_cefe {
  strings:
    $key_cefe = { 9d 91 [2] b9 9f [2] 92 b3 [2] bc 91 [2] a8 8a [2] a7 90 [2] b9 8d [2] bb 8c [2] a0 8a [2] bc 8d [2] a0 a2 }

  condition:
    any of them
}