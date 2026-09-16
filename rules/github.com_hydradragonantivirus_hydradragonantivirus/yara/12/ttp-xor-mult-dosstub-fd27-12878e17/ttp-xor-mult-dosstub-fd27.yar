rule TTP_XOR_MULT_DOSStub_fd27 {
  strings:
    $key_fd27 = { a9 4f [2] dd 57 [2] 9a 55 [2] dd 44 [2] 93 48 [2] 9f 42 [2] 88 49 [2] 93 07 [2] ae }

  condition:
    any of them
}