rule TTP_XOR_QUAD_CurrentVersionRun_cbda {
  strings:
    $key_cbda = { 98 b5 [2] bc bb [2] 97 97 [2] b9 b5 [2] ad ae [2] a2 b4 [2] bc a9 [2] be a8 [2] a5 ae [2] b9 a9 [2] a5 86 }

  condition:
    any of them
}