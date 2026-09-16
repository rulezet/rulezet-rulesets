rule TTP_XOR_MULT_DOSStub_fd89 {
  strings:
    $key_fd89 = { a9 e1 [2] dd f9 [2] 9a fb [2] dd ea [2] 93 e6 [2] 9f ec [2] 88 e7 [2] 93 a9 [2] ae }

  condition:
    any of them
}