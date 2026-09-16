rule TTP_XOR_MULT_DOSStub_fd72 {
  strings:
    $key_fd72 = { a9 1a [2] dd 02 [2] 9a 00 [2] dd 11 [2] 93 1d [2] 9f 17 [2] 88 1c [2] 93 52 [2] ae }

  condition:
    any of them
}