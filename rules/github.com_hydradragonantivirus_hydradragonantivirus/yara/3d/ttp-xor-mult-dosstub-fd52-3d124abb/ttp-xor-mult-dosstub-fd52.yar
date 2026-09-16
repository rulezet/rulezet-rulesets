rule TTP_XOR_MULT_DOSStub_fd52 {
  strings:
    $key_fd52 = { a9 3a [2] dd 22 [2] 9a 20 [2] dd 31 [2] 93 3d [2] 9f 37 [2] 88 3c [2] 93 72 [2] ae }

  condition:
    any of them
}