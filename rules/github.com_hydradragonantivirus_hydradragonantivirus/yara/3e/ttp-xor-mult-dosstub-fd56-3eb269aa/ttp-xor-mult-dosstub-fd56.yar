rule TTP_XOR_MULT_DOSStub_fd56 {
  strings:
    $key_fd56 = { a9 3e [2] dd 26 [2] 9a 24 [2] dd 35 [2] 93 39 [2] 9f 33 [2] 88 38 [2] 93 76 [2] ae }

  condition:
    any of them
}