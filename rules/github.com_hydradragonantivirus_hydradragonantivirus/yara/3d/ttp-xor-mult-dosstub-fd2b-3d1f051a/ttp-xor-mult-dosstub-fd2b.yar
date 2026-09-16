rule TTP_XOR_MULT_DOSStub_fd2b {
  strings:
    $key_fd2b = { a9 43 [2] dd 5b [2] 9a 59 [2] dd 48 [2] 93 44 [2] 9f 4e [2] 88 45 [2] 93 0b [2] ae }

  condition:
    any of them
}