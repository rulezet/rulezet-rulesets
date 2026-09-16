rule TTP_XOR_MULT_DOSStub_adbc {
  strings:
    $key_adbc = { f9 d4 [2] 8d cc [2] ca ce [2] 8d df [2] c3 d3 [2] cf d9 [2] d8 d2 [2] c3 9c [2] fe }

  condition:
    any of them
}