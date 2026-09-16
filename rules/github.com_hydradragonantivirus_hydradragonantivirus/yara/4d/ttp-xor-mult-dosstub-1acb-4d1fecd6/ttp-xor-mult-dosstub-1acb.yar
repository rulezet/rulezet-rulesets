rule TTP_XOR_MULT_DOSStub_1acb {
  strings:
    $key_1acb = { 4e a3 [2] 3a bb [2] 7d b9 [2] 3a a8 [2] 74 a4 [2] 78 ae [2] 6f a5 [2] 74 eb [2] 49 }

  condition:
    any of them
}