rule TTP_XOR_MULT_DOSStub_dcab {
  strings:
    $key_dcab = { 88 c3 [2] fc db [2] bb d9 [2] fc c8 [2] b2 c4 [2] be ce [2] a9 c5 [2] b2 8b [2] 8f }

  condition:
    any of them
}