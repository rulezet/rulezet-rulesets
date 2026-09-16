rule TTP_XOR_MULT_DOSStub_fd70 {
  strings:
    $key_fd70 = { a9 18 [2] dd 00 [2] 9a 02 [2] dd 13 [2] 93 1f [2] 9f 15 [2] 88 1e [2] 93 50 [2] ae }

  condition:
    any of them
}