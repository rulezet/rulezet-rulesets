rule TTP_XOR_MULT_DOSStub_adb3 {
  strings:
    $key_adb3 = { f9 db [2] 8d c3 [2] ca c1 [2] 8d d0 [2] c3 dc [2] cf d6 [2] d8 dd [2] c3 93 [2] fe }

  condition:
    any of them
}