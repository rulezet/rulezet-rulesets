rule TTP_XOR_MULT_DOSStub_fd22 {
  strings:
    $key_fd22 = { a9 4a [2] dd 52 [2] 9a 50 [2] dd 41 [2] 93 4d [2] 9f 47 [2] 88 4c [2] 93 02 [2] ae }

  condition:
    any of them
}