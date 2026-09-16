rule TTP_XOR_MULT_DOSStub_88dd {
  strings:
    $key_88dd = { dc b5 [2] a8 ad [2] ef af [2] a8 be [2] e6 b2 [2] ea b8 [2] fd b3 [2] e6 fd [2] db }

  condition:
    any of them
}