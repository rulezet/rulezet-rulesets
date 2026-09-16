rule TTP_XOR_MULT_DOSStub_adb6 {
  strings:
    $key_adb6 = { f9 de [2] 8d c6 [2] ca c4 [2] 8d d5 [2] c3 d9 [2] cf d3 [2] d8 d8 [2] c3 96 [2] fe }

  condition:
    any of them
}