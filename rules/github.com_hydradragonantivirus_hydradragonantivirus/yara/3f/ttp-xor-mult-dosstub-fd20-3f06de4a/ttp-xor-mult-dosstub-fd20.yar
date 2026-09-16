rule TTP_XOR_MULT_DOSStub_fd20 {
  strings:
    $key_fd20 = { a9 48 [2] dd 50 [2] 9a 52 [2] dd 43 [2] 93 4f [2] 9f 45 [2] 88 4e [2] 93 00 [2] ae }

  condition:
    any of them
}