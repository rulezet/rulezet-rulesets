rule TTP_XOR_MULT_DOSStub_e927 {
  strings:
    $key_e927 = { bd 4f [2] c9 57 [2] 8e 55 [2] c9 44 [2] 87 48 [2] 8b 42 [2] 9c 49 [2] 87 07 [2] ba }

  condition:
    any of them
}