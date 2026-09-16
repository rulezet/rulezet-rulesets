rule TTP_XOR_MULT_DOSStub_3fcb {
  strings:
    $key_3fcb = { 6b a3 [2] 1f bb [2] 58 b9 [2] 1f a8 [2] 51 a4 [2] 5d ae [2] 4a a5 [2] 51 eb [2] 6c }

  condition:
    any of them
}