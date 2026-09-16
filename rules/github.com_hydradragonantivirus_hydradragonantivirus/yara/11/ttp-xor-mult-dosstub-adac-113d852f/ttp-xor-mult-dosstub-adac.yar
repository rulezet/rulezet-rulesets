rule TTP_XOR_MULT_DOSStub_adac {
  strings:
    $key_adac = { f9 c4 [2] 8d dc [2] ca de [2] 8d cf [2] c3 c3 [2] cf c9 [2] d8 c2 [2] c3 8c [2] fe }

  condition:
    any of them
}