rule TTP_XOR_MULT_DOSStub_fd4b {
  strings:
    $key_fd4b = { a9 23 [2] dd 3b [2] 9a 39 [2] dd 28 [2] 93 24 [2] 9f 2e [2] 88 25 [2] 93 6b [2] ae }

  condition:
    any of them
}