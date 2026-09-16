rule TTP_XOR_MULT_DOSStub_fdcc {
  strings:
    $key_fdcc = { a9 a4 [2] dd bc [2] 9a be [2] dd af [2] 93 a3 [2] 9f a9 [2] 88 a2 [2] 93 ec [2] ae }

  condition:
    any of them
}