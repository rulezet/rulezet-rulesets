rule TTP_XOR_MULT_DOSStub_fd37 {
  strings:
    $key_fd37 = { a9 5f [2] dd 47 [2] 9a 45 [2] dd 54 [2] 93 58 [2] 9f 52 [2] 88 59 [2] 93 17 [2] ae }

  condition:
    any of them
}