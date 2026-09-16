rule TTP_XOR_MULT_DOSStub_fd49 {
  strings:
    $key_fd49 = { a9 21 [2] dd 39 [2] 9a 3b [2] dd 2a [2] 93 26 [2] 9f 2c [2] 88 27 [2] 93 69 [2] ae }

  condition:
    any of them
}