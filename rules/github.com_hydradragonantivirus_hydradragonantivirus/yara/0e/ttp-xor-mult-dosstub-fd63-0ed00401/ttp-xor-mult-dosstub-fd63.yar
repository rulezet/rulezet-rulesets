rule TTP_XOR_MULT_DOSStub_fd63 {
  strings:
    $key_fd63 = { a9 0b [2] dd 13 [2] 9a 11 [2] dd 00 [2] 93 0c [2] 9f 06 [2] 88 0d [2] 93 43 [2] ae }

  condition:
    any of them
}