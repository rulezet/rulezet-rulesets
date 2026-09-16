rule TTP_XOR_MULT_DOSStub_adda {
  strings:
    $key_adda = { f9 b2 [2] 8d aa [2] ca a8 [2] 8d b9 [2] c3 b5 [2] cf bf [2] d8 b4 [2] c3 fa [2] fe }

  condition:
    any of them
}