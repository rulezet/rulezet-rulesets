rule TTP_XOR_MULT_DOSStub_fd50 {
  strings:
    $key_fd50 = { a9 38 [2] dd 20 [2] 9a 22 [2] dd 33 [2] 93 3f [2] 9f 35 [2] 88 3e [2] 93 70 [2] ae }

  condition:
    any of them
}