rule TTP_XOR_MULT_DOSStub_fd38 {
  strings:
    $key_fd38 = { a9 50 [2] dd 48 [2] 9a 4a [2] dd 5b [2] 93 57 [2] 9f 5d [2] 88 56 [2] 93 18 [2] ae }

  condition:
    any of them
}