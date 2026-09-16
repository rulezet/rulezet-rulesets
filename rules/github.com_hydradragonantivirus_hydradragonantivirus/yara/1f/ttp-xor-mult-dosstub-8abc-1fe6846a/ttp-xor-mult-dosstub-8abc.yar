rule TTP_XOR_MULT_DOSStub_8abc {
  strings:
    $key_8abc = { de d4 [2] aa cc [2] ed ce [2] aa df [2] e4 d3 [2] e8 d9 [2] ff d2 [2] e4 9c [2] d9 }

  condition:
    any of them
}