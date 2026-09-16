rule TTP_XOR_MULT_DOSStub_bdb8 {
  strings:
    $key_bdb8 = { e9 d0 [2] 9d c8 [2] da ca [2] 9d db [2] d3 d7 [2] df dd [2] c8 d6 [2] d3 98 [2] ee }

  condition:
    any of them
}