rule TTP_XOR_MULT_DOSStub_fd65 {
  strings:
    $key_fd65 = { a9 0d [2] dd 15 [2] 9a 17 [2] dd 06 [2] 93 0a [2] 9f 00 [2] 88 0b [2] 93 45 [2] ae }

  condition:
    any of them
}