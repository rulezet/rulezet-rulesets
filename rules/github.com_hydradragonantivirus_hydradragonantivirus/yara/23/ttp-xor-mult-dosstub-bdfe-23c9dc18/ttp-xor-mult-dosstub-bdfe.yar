rule TTP_XOR_MULT_DOSStub_bdfe {
  strings:
    $key_bdfe = { e9 96 [2] 9d 8e [2] da 8c [2] 9d 9d [2] d3 91 [2] df 9b [2] c8 90 [2] d3 de [2] ee }

  condition:
    any of them
}