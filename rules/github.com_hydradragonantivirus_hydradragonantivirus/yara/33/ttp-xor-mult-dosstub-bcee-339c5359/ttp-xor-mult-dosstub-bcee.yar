rule TTP_XOR_MULT_DOSStub_bcee {
  strings:
    $key_bcee = { e8 86 [2] 9c 9e [2] db 9c [2] 9c 8d [2] d2 81 [2] de 8b [2] c9 80 [2] d2 ce [2] ef }

  condition:
    any of them
}