rule TTP_XOR_MULT_DOSStub_add6 {
  strings:
    $key_add6 = { f9 be [2] 8d a6 [2] ca a4 [2] 8d b5 [2] c3 b9 [2] cf b3 [2] d8 b8 [2] c3 f6 [2] fe }

  condition:
    any of them
}