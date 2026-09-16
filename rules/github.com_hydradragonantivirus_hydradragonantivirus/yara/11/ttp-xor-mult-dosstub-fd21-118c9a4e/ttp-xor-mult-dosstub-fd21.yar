rule TTP_XOR_MULT_DOSStub_fd21 {
  strings:
    $key_fd21 = { a9 49 [2] dd 51 [2] 9a 53 [2] dd 42 [2] 93 4e [2] 9f 44 [2] 88 4f [2] 93 01 [2] ae }

  condition:
    any of them
}