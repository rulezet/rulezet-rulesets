rule TTP_XOR_MULT_DOSStub_eccb {
  strings:
    $key_eccb = { b8 a3 [2] cc bb [2] 8b b9 [2] cc a8 [2] 82 a4 [2] 8e ae [2] 99 a5 [2] 82 eb [2] bf }

  condition:
    any of them
}