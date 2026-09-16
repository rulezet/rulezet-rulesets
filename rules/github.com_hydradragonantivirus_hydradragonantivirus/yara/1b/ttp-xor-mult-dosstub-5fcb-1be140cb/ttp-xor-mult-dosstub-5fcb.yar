rule TTP_XOR_MULT_DOSStub_5fcb {
  strings:
    $key_5fcb = { 0b a3 [2] 7f bb [2] 38 b9 [2] 7f a8 [2] 31 a4 [2] 3d ae [2] 2a a5 [2] 31 eb [2] 0c }

  condition:
    any of them
}