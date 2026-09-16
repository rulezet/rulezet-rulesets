rule TTP_XOR_MULT_DOSStub_fd10 {
  strings:
    $key_fd10 = { a9 78 [2] dd 60 [2] 9a 62 [2] dd 73 [2] 93 7f [2] 9f 75 [2] 88 7e [2] 93 30 [2] ae }

  condition:
    any of them
}