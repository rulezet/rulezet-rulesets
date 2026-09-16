rule TTP_XOR_MULT_DOSStub_fd17 {
  strings:
    $key_fd17 = { a9 7f [2] dd 67 [2] 9a 65 [2] dd 74 [2] 93 78 [2] 9f 72 [2] 88 79 [2] 93 37 [2] ae }

  condition:
    any of them
}