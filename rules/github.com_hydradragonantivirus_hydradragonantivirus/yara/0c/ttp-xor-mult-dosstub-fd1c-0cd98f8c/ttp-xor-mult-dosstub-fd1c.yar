rule TTP_XOR_MULT_DOSStub_fd1c {
  strings:
    $key_fd1c = { a9 74 [2] dd 6c [2] 9a 6e [2] dd 7f [2] 93 73 [2] 9f 79 [2] 88 72 [2] 93 3c [2] ae }

  condition:
    any of them
}