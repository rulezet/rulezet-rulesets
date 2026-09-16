rule TTP_XOR_MULT_DOSStub_add2 {
  strings:
    $key_add2 = { f9 ba [2] 8d a2 [2] ca a0 [2] 8d b1 [2] c3 bd [2] cf b7 [2] d8 bc [2] c3 f2 [2] fe }

  condition:
    any of them
}