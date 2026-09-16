rule TTP_XOR_MULT_DOSStub_bdfd {
  strings:
    $key_bdfd = { e9 95 [2] 9d 8d [2] da 8f [2] 9d 9e [2] d3 92 [2] df 98 [2] c8 93 [2] d3 dd [2] ee }

  condition:
    any of them
}