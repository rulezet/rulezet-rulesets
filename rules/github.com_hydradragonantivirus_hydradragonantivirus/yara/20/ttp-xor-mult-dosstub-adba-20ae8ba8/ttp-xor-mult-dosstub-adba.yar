rule TTP_XOR_MULT_DOSStub_adba {
  strings:
    $key_adba = { f9 d2 [2] 8d ca [2] ca c8 [2] 8d d9 [2] c3 d5 [2] cf df [2] d8 d4 [2] c3 9a [2] fe }

  condition:
    any of them
}