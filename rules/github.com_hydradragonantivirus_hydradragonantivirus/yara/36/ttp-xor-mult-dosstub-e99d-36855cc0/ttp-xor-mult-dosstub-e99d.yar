rule TTP_XOR_MULT_DOSStub_e99d {
  strings:
    $key_e99d = { bd f5 [2] c9 ed [2] 8e ef [2] c9 fe [2] 87 f2 [2] 8b f8 [2] 9c f3 [2] 87 bd [2] ba }

  condition:
    any of them
}