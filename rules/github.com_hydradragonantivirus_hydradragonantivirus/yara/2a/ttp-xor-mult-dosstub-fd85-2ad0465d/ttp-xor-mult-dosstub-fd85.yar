rule TTP_XOR_MULT_DOSStub_fd85 {
  strings:
    $key_fd85 = { a9 ed [2] dd f5 [2] 9a f7 [2] dd e6 [2] 93 ea [2] 9f e0 [2] 88 eb [2] 93 a5 [2] ae }

  condition:
    any of them
}