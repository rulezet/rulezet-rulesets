rule TTP_XOR_MULT_DOSStub_add3 {
  strings:
    $key_add3 = { f9 bb [2] 8d a3 [2] ca a1 [2] 8d b0 [2] c3 bc [2] cf b6 [2] d8 bd [2] c3 f3 [2] fe }

  condition:
    any of them
}