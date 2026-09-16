rule TTP_XOR_MULT_DOSStub_e977 {
  strings:
    $key_e977 = { bd 1f [2] c9 07 [2] 8e 05 [2] c9 14 [2] 87 18 [2] 8b 12 [2] 9c 19 [2] 87 57 [2] ba }

  condition:
    any of them
}