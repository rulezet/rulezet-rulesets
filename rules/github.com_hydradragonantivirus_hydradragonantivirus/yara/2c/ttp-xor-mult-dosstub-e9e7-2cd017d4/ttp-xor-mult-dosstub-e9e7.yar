rule TTP_XOR_MULT_DOSStub_e9e7 {
  strings:
    $key_e9e7 = { bd 8f [2] c9 97 [2] 8e 95 [2] c9 84 [2] 87 88 [2] 8b 82 [2] 9c 89 [2] 87 c7 [2] ba }

  condition:
    any of them
}