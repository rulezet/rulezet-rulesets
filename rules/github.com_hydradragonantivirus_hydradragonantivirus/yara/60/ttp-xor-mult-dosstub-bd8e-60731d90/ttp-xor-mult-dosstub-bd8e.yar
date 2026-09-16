rule TTP_XOR_MULT_DOSStub_bd8e {
  strings:
    $key_bd8e = { e9 e6 [2] 9d fe [2] da fc [2] 9d ed [2] d3 e1 [2] df eb [2] c8 e0 [2] d3 ae [2] ee }

  condition:
    any of them
}