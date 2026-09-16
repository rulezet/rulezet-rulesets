rule TTP_XOR_MULT_DOSStub_0fcb {
  strings:
    $key_0fcb = { 5b a3 [2] 2f bb [2] 68 b9 [2] 2f a8 [2] 61 a4 [2] 6d ae [2] 7a a5 [2] 61 eb [2] 5c }

  condition:
    any of them
}