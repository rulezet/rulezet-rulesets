rule TTP_XOR_MULT_DOSStub_fd42 {
  strings:
    $key_fd42 = { a9 2a [2] dd 32 [2] 9a 30 [2] dd 21 [2] 93 2d [2] 9f 27 [2] 88 2c [2] 93 62 [2] ae }

  condition:
    any of them
}