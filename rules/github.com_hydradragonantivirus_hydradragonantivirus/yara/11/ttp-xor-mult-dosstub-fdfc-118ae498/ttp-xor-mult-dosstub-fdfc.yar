rule TTP_XOR_MULT_DOSStub_fdfc {
  strings:
    $key_fdfc = { a9 94 [2] dd 8c [2] 9a 8e [2] dd 9f [2] 93 93 [2] 9f 99 [2] 88 92 [2] 93 dc [2] ae }

  condition:
    any of them
}