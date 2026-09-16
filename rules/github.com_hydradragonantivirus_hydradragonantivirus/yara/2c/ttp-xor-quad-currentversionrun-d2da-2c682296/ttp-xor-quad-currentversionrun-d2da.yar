rule TTP_XOR_QUAD_CurrentVersionRun_d2da {
  strings:
    $key_d2da = { 81 b5 [2] a5 bb [2] 8e 97 [2] a0 b5 [2] b4 ae [2] bb b4 [2] a5 a9 [2] a7 a8 [2] bc ae [2] a0 a9 [2] bc 86 }

  condition:
    any of them
}