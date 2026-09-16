rule TTP_XOR_MULT_DOSStub_adfb {
  strings:
    $key_adfb = { f9 93 [2] 8d 8b [2] ca 89 [2] 8d 98 [2] c3 94 [2] cf 9e [2] d8 95 [2] c3 db [2] fe }

  condition:
    any of them
}