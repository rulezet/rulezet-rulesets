rule TTP_XOR_MULT_DOSStub_e940 {
  strings:
    $key_e940 = { bd 28 [2] c9 30 [2] 8e 32 [2] c9 23 [2] 87 2f [2] 8b 25 [2] 9c 2e [2] 87 60 [2] ba }

  condition:
    any of them
}