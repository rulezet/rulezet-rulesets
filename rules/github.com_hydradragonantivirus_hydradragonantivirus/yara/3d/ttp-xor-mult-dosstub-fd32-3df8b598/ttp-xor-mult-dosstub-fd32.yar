rule TTP_XOR_MULT_DOSStub_fd32 {
  strings:
    $key_fd32 = { a9 5a [2] dd 42 [2] 9a 40 [2] dd 51 [2] 93 5d [2] 9f 57 [2] 88 5c [2] 93 12 [2] ae }

  condition:
    any of them
}