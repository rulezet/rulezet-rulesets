rule TTP_XOR_MULT_DOSStub_fecc {
  strings:
    $key_fecc = { aa a4 [2] de bc [2] 99 be [2] de af [2] 90 a3 [2] 9c a9 [2] 8b a2 [2] 90 ec [2] ad }

  condition:
    any of them
}