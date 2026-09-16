rule TTP_XOR_MULT_DOSStub_adb8 {
  strings:
    $key_adb8 = { f9 d0 [2] 8d c8 [2] ca ca [2] 8d db [2] c3 d7 [2] cf dd [2] d8 d6 [2] c3 98 [2] fe }

  condition:
    any of them
}