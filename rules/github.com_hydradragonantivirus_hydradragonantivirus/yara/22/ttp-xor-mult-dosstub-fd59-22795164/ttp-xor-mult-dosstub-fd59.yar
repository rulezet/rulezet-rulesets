rule TTP_XOR_MULT_DOSStub_fd59 {
  strings:
    $key_fd59 = { a9 31 [2] dd 29 [2] 9a 2b [2] dd 3a [2] 93 36 [2] 9f 3c [2] 88 37 [2] 93 79 [2] ae }

  condition:
    any of them
}