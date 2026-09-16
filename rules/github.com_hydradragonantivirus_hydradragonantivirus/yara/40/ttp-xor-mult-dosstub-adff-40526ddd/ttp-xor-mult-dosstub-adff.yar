rule TTP_XOR_MULT_DOSStub_adff {
  strings:
    $key_adff = { f9 97 [2] 8d 8f [2] ca 8d [2] 8d 9c [2] c3 90 [2] cf 9a [2] d8 91 [2] c3 df [2] fe }

  condition:
    any of them
}