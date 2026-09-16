rule TTP_XOR_MULT_DOSStub_dfcb {
  strings:
    $key_dfcb = { 8b a3 [2] ff bb [2] b8 b9 [2] ff a8 [2] b1 a4 [2] bd ae [2] aa a5 [2] b1 eb [2] 8c }

  condition:
    any of them
}