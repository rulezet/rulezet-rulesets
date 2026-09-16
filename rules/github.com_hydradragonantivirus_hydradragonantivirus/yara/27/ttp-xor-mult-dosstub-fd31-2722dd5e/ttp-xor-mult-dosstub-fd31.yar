rule TTP_XOR_MULT_DOSStub_fd31 {
  strings:
    $key_fd31 = { a9 59 [2] dd 41 [2] 9a 43 [2] dd 52 [2] 93 5e [2] 9f 54 [2] 88 5f [2] 93 11 [2] ae }

  condition:
    any of them
}