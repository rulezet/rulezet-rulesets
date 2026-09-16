rule TTP_XOR_MULT_DOSStub_fd76 {
  strings:
    $key_fd76 = { a9 1e [2] dd 06 [2] 9a 04 [2] dd 15 [2] 93 19 [2] 9f 13 [2] 88 18 [2] 93 56 [2] ae }

  condition:
    any of them
}