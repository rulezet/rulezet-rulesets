rule TTP_XOR_MULT_DOSStub_fd54 {
  strings:
    $key_fd54 = { a9 3c [2] dd 24 [2] 9a 26 [2] dd 37 [2] 93 3b [2] 9f 31 [2] 88 3a [2] 93 74 [2] ae }

  condition:
    any of them
}