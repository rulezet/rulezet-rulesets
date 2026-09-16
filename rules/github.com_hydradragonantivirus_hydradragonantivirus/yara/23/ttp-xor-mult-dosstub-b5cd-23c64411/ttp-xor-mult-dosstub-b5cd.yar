rule TTP_XOR_MULT_DOSStub_b5cd {
  strings:
    $key_b5cd = { e1 a5 [2] 95 bd [2] d2 bf [2] 95 ae [2] db a2 [2] d7 a8 [2] c0 a3 [2] db ed [2] e6 }

  condition:
    any of them
}