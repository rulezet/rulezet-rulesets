rule TTP_XOR_MULT_DOSStub_fd82 {
  strings:
    $key_fd82 = { a9 ea [2] dd f2 [2] 9a f0 [2] dd e1 [2] 93 ed [2] 9f e7 [2] 88 ec [2] 93 a2 [2] ae }

  condition:
    any of them
}