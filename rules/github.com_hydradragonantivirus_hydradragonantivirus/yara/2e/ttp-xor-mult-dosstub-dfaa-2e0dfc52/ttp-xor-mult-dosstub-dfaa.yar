rule TTP_XOR_MULT_DOSStub_dfaa {
  strings:
    $key_dfaa = { 8b c2 [2] ff da [2] b8 d8 [2] ff c9 [2] b1 c5 [2] bd cf [2] aa c4 [2] b1 8a [2] 8c }

  condition:
    any of them
}