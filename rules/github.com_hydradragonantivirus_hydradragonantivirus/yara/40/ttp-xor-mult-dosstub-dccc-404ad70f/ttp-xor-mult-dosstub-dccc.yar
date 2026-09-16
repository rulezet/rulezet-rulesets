rule TTP_XOR_MULT_DOSStub_dccc {
  strings:
    $key_dccc = { 88 a4 [2] fc bc [2] bb be [2] fc af [2] b2 a3 [2] be a9 [2] a9 a2 [2] b2 ec [2] 8f }

  condition:
    any of them
}