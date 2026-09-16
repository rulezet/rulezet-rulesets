rule TTP_XOR_MULT_DOSStub_fdee {
  strings:
    $key_fdee = { a9 86 [2] dd 9e [2] 9a 9c [2] dd 8d [2] 93 81 [2] 9f 8b [2] 88 80 [2] 93 ce [2] ae }

  condition:
    any of them
}