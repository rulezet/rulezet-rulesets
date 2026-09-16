rule TTP_XOR_MULT_DOSStub_bdae {
  strings:
    $key_bdae = { e9 c6 [2] 9d de [2] da dc [2] 9d cd [2] d3 c1 [2] df cb [2] c8 c0 [2] d3 8e [2] ee }

  condition:
    any of them
}