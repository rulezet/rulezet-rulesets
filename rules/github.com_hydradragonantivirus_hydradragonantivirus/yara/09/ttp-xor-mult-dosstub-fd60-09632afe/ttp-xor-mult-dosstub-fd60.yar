rule TTP_XOR_MULT_DOSStub_fd60 {
  strings:
    $key_fd60 = { a9 08 [2] dd 10 [2] 9a 12 [2] dd 03 [2] 93 0f [2] 9f 05 [2] 88 0e [2] 93 40 [2] ae }

  condition:
    any of them
}