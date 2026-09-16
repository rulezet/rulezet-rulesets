rule TTP_XOR_MULT_DOSStub_bd8d {
  strings:
    $key_bd8d = { e9 e5 [2] 9d fd [2] da ff [2] 9d ee [2] d3 e2 [2] df e8 [2] c8 e3 [2] d3 ad [2] ee }

  condition:
    any of them
}