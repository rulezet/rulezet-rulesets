rule TTP_XOR_MULT_DOSStub_fd7c {
  strings:
    $key_fd7c = { a9 14 [2] dd 0c [2] 9a 0e [2] dd 1f [2] 93 13 [2] 9f 19 [2] 88 12 [2] 93 5c [2] ae }

  condition:
    any of them
}