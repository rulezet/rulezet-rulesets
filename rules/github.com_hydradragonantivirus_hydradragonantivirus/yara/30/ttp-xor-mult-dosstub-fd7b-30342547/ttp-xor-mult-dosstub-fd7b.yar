rule TTP_XOR_MULT_DOSStub_fd7b {
  strings:
    $key_fd7b = { a9 13 [2] dd 0b [2] 9a 09 [2] dd 18 [2] 93 14 [2] 9f 1e [2] 88 15 [2] 93 5b [2] ae }

  condition:
    any of them
}