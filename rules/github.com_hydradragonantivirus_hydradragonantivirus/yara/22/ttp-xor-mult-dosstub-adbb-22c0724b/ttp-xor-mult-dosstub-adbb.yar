rule TTP_XOR_MULT_DOSStub_adbb {
  strings:
    $key_adbb = { f9 d3 [2] 8d cb [2] ca c9 [2] 8d d8 [2] c3 d4 [2] cf de [2] d8 d5 [2] c3 9b [2] fe }

  condition:
    any of them
}