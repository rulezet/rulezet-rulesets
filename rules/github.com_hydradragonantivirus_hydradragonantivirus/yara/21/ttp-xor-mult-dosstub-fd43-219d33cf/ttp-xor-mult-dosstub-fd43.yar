rule TTP_XOR_MULT_DOSStub_fd43 {
  strings:
    $key_fd43 = { a9 2b [2] dd 33 [2] 9a 31 [2] dd 20 [2] 93 2c [2] 9f 26 [2] 88 2d [2] 93 63 [2] ae }

  condition:
    any of them
}