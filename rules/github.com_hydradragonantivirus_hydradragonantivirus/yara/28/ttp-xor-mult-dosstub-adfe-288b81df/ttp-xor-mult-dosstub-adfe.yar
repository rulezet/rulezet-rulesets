rule TTP_XOR_MULT_DOSStub_adfe {
  strings:
    $key_adfe = { f9 96 [2] 8d 8e [2] ca 8c [2] 8d 9d [2] c3 91 [2] cf 9b [2] d8 90 [2] c3 de [2] fe }

  condition:
    any of them
}