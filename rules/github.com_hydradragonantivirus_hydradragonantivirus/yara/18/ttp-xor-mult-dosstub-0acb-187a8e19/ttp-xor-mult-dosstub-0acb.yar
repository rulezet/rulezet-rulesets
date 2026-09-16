rule TTP_XOR_MULT_DOSStub_0acb {
  strings:
    $key_0acb = { 5e a3 [2] 2a bb [2] 6d b9 [2] 2a a8 [2] 64 a4 [2] 68 ae [2] 7f a5 [2] 64 eb [2] 59 }

  condition:
    any of them
}