rule TTP_XOR_MULT_DOSStub_dfca {
  strings:
    $key_dfca = { 8b a2 [2] ff ba [2] b8 b8 [2] ff a9 [2] b1 a5 [2] bd af [2] aa a4 [2] b1 ea [2] 8c }

  condition:
    any of them
}