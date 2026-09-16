rule TTP_XOR_MULT_DOSStub_bd83 {
  strings:
    $key_bd83 = { e9 eb [2] 9d f3 [2] da f1 [2] 9d e0 [2] d3 ec [2] df e6 [2] c8 ed [2] d3 a3 [2] ee }

  condition:
    any of them
}