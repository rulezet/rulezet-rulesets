rule TTP_XOR_MULT_DOSStub_fd06 {
  strings:
    $key_fd06 = { a9 6e [2] dd 76 [2] 9a 74 [2] dd 65 [2] 93 69 [2] 9f 63 [2] 88 68 [2] 93 26 [2] ae }

  condition:
    any of them
}