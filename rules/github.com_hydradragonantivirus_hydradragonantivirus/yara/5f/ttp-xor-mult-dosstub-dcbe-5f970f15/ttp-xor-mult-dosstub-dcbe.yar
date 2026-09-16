rule TTP_XOR_MULT_DOSStub_dcbe {
  strings:
    $key_dcbe = { 88 d6 [2] fc ce [2] bb cc [2] fc dd [2] b2 d1 [2] be db [2] a9 d0 [2] b2 9e [2] 8f }

  condition:
    any of them
}