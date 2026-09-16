rule TTP_XOR_MULT_DOSStub_e957 {
  strings:
    $key_e957 = { bd 3f [2] c9 27 [2] 8e 25 [2] c9 34 [2] 87 38 [2] 8b 32 [2] 9c 39 [2] 87 77 [2] ba }

  condition:
    any of them
}