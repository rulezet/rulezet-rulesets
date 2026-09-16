rule TTP_XOR_MULT_DOSStub_b1be {
  strings:
    $key_b1be = { e5 d6 [2] 91 ce [2] d6 cc [2] 91 dd [2] df d1 [2] d3 db [2] c4 d0 [2] df 9e [2] e2 }

  condition:
    any of them
}