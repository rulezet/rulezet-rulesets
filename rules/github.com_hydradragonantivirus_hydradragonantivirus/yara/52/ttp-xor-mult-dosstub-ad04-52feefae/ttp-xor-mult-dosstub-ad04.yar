rule TTP_XOR_MULT_DOSStub_ad04 {
  strings:
    $key_ad04 = { f9 6c [2] 8d 74 [2] ca 76 [2] 8d 67 [2] c3 6b [2] cf 61 [2] d8 6a [2] c3 24 [2] fe }

  condition:
    any of them
}