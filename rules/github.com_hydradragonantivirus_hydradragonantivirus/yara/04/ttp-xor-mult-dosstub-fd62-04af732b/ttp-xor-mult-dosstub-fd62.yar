rule TTP_XOR_MULT_DOSStub_fd62 {
  strings:
    $key_fd62 = { a9 0a [2] dd 12 [2] 9a 10 [2] dd 01 [2] 93 0d [2] 9f 07 [2] 88 0c [2] 93 42 [2] ae }

  condition:
    any of them
}