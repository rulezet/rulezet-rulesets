rule TTP_XOR_MULT_DOSStub_fd3f {
  strings:
    $key_fd3f = { a9 57 [2] dd 4f [2] 9a 4d [2] dd 5c [2] 93 50 [2] 9f 5a [2] 88 51 [2] 93 1f [2] ae }

  condition:
    any of them
}