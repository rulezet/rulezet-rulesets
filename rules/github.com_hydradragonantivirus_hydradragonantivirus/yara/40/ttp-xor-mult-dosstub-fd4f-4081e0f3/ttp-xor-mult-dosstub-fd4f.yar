rule TTP_XOR_MULT_DOSStub_fd4f {
  strings:
    $key_fd4f = { a9 27 [2] dd 3f [2] 9a 3d [2] dd 2c [2] 93 20 [2] 9f 2a [2] 88 21 [2] 93 6f [2] ae }

  condition:
    any of them
}