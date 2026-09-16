rule TTP_XOR_MULT_DOSStub_cfab {
  strings:
    $key_cfab = { 9b c3 [2] ef db [2] a8 d9 [2] ef c8 [2] a1 c4 [2] ad ce [2] ba c5 [2] a1 8b [2] 9c }

  condition:
    any of them
}