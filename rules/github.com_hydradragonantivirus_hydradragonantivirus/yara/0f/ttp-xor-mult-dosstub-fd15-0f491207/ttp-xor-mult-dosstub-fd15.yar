rule TTP_XOR_MULT_DOSStub_fd15 {
  strings:
    $key_fd15 = { a9 7d [2] dd 65 [2] 9a 67 [2] dd 76 [2] 93 7a [2] 9f 70 [2] 88 7b [2] 93 35 [2] ae }

  condition:
    any of them
}