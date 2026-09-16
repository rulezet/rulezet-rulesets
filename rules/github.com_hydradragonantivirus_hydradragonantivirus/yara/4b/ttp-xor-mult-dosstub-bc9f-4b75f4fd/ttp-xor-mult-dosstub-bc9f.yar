rule TTP_XOR_MULT_DOSStub_bc9f {
  strings:
    $key_bc9f = { e8 f7 [2] 9c ef [2] db ed [2] 9c fc [2] d2 f0 [2] de fa [2] c9 f1 [2] d2 bf [2] ef }

  condition:
    any of them
}