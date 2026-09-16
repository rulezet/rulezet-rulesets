rule TTP_XOR_MULT_DOSStub_bd03 {
  strings:
    $key_bd03 = { e9 6b [2] 9d 73 [2] da 71 [2] 9d 60 [2] d3 6c [2] df 66 [2] c8 6d [2] d3 23 [2] ee }

  condition:
    any of them
}