rule TTP_XOR_MULT_DOSStub_fec6 {
  strings:
    $key_fec6 = { aa ae [2] de b6 [2] 99 b4 [2] de a5 [2] 90 a9 [2] 9c a3 [2] 8b a8 [2] 90 e6 [2] ad }

  condition:
    any of them
}