rule TTP_XOR_MULT_DOSStub_fd3c {
  strings:
    $key_fd3c = { a9 54 [2] dd 4c [2] 9a 4e [2] dd 5f [2] 93 53 [2] 9f 59 [2] 88 52 [2] 93 1c [2] ae }

  condition:
    any of them
}