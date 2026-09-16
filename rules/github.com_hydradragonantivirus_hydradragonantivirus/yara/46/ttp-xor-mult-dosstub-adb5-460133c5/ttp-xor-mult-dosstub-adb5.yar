rule TTP_XOR_MULT_DOSStub_adb5 {
  strings:
    $key_adb5 = { f9 dd [2] 8d c5 [2] ca c7 [2] 8d d6 [2] c3 da [2] cf d0 [2] d8 db [2] c3 95 [2] fe }

  condition:
    any of them
}