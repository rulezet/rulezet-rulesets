rule TTP_XOR_MULT_DOSStub_fd88 {
  strings:
    $key_fd88 = { a9 e0 [2] dd f8 [2] 9a fa [2] dd eb [2] 93 e7 [2] 9f ed [2] 88 e6 [2] 93 a8 [2] ae }

  condition:
    any of them
}