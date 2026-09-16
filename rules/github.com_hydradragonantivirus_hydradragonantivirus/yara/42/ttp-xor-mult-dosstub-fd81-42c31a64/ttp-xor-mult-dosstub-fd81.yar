rule TTP_XOR_MULT_DOSStub_fd81 {
  strings:
    $key_fd81 = { a9 e9 [2] dd f1 [2] 9a f3 [2] dd e2 [2] 93 ee [2] 9f e4 [2] 88 ef [2] 93 a1 [2] ae }

  condition:
    any of them
}