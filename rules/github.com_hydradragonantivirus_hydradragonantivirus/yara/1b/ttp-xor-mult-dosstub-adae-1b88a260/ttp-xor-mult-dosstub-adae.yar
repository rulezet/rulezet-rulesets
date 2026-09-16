rule TTP_XOR_MULT_DOSStub_adae {
  strings:
    $key_adae = { f9 c6 [2] 8d de [2] ca dc [2] 8d cd [2] c3 c1 [2] cf cb [2] d8 c0 [2] c3 8e [2] fe }

  condition:
    any of them
}