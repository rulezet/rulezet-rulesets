rule TTP_XOR_MULT_DOSStub_dfde {
  strings:
    $key_dfde = { 8b b6 [2] ff ae [2] b8 ac [2] ff bd [2] b1 b1 [2] bd bb [2] aa b0 [2] b1 fe [2] 8c }

  condition:
    any of them
}