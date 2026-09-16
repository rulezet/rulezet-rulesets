rule TTP_XOR_MULT_DOSStub_fd3b {
  strings:
    $key_fd3b = { a9 53 [2] dd 4b [2] 9a 49 [2] dd 58 [2] 93 54 [2] 9f 5e [2] 88 55 [2] 93 1b [2] ae }

  condition:
    any of them
}