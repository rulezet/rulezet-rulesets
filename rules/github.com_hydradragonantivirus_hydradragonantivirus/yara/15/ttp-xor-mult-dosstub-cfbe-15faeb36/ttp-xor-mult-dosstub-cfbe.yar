rule TTP_XOR_MULT_DOSStub_cfbe {
  strings:
    $key_cfbe = { 9b d6 [2] ef ce [2] a8 cc [2] ef dd [2] a1 d1 [2] ad db [2] ba d0 [2] a1 9e [2] 9c }

  condition:
    any of them
}