rule TTP_XOR_MULT_DOSStub_dacb {
  strings:
    $key_dacb = { 8e a3 [2] fa bb [2] bd b9 [2] fa a8 [2] b4 a4 [2] b8 ae [2] af a5 [2] b4 eb [2] 89 }

  condition:
    any of them
}