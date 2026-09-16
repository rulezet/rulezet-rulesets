rule TTP_XOR_MULT_DOSStub_add5 {
  strings:
    $key_add5 = { f9 bd [2] 8d a5 [2] ca a7 [2] 8d b6 [2] c3 ba [2] cf b0 [2] d8 bb [2] c3 f5 [2] fe }

  condition:
    any of them
}