rule TTP_XOR_MULT_DOSStub_2fcb {
  strings:
    $key_2fcb = { 7b a3 [2] 0f bb [2] 48 b9 [2] 0f a8 [2] 41 a4 [2] 4d ae [2] 5a a5 [2] 41 eb [2] 7c }

  condition:
    any of them
}