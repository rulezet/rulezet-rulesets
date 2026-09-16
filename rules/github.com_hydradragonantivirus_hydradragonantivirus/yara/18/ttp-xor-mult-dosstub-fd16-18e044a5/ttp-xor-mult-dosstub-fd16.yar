rule TTP_XOR_MULT_DOSStub_fd16 {
  strings:
    $key_fd16 = { a9 7e [2] dd 66 [2] 9a 64 [2] dd 75 [2] 93 79 [2] 9f 73 [2] 88 78 [2] 93 36 [2] ae }

  condition:
    any of them
}