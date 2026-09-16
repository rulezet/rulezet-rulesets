rule TTP_XOR_MULT_DOSStub_fd3a {
  strings:
    $key_fd3a = { a9 52 [2] dd 4a [2] 9a 48 [2] dd 59 [2] 93 55 [2] 9f 5f [2] 88 54 [2] 93 1a [2] ae }

  condition:
    any of them
}