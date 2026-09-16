rule TTP_XOR_MULT_DOSStub_ad58 {
  strings:
    $key_ad58 = { f9 30 [2] 8d 28 [2] ca 2a [2] 8d 3b [2] c3 37 [2] cf 3d [2] d8 36 [2] c3 78 [2] fe }

  condition:
    any of them
}