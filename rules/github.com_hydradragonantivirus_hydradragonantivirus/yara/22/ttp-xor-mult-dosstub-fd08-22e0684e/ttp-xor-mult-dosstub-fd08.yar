rule TTP_XOR_MULT_DOSStub_fd08 {
  strings:
    $key_fd08 = { a9 60 [2] dd 78 [2] 9a 7a [2] dd 6b [2] 93 67 [2] 9f 6d [2] 88 66 [2] 93 28 [2] ae }

  condition:
    any of them
}