rule TTP_XOR_MULT_DOSStub_bd99 {
  strings:
    $key_bd99 = { e9 f1 [2] 9d e9 [2] da eb [2] 9d fa [2] d3 f6 [2] df fc [2] c8 f7 [2] d3 b9 [2] ee }

  condition:
    any of them
}