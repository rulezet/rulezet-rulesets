rule TTP_XOR_MULT_DOSStub_fd7a {
  strings:
    $key_fd7a = { a9 12 [2] dd 0a [2] 9a 08 [2] dd 19 [2] 93 15 [2] 9f 1f [2] 88 14 [2] 93 5a [2] ae }

  condition:
    any of them
}