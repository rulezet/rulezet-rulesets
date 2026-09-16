rule TTP_XOR_MULT_DOSStub_caee {
  strings:
    $key_caee = { 9e 86 [2] ea 9e [2] ad 9c [2] ea 8d [2] a4 81 [2] a8 8b [2] bf 80 [2] a4 ce [2] 99 }

  condition:
    any of them
}