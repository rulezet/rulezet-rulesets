rule TTP_XOR_MULT_DOSStub_e936 {
  strings:
    $key_e936 = { bd 5e [2] c9 46 [2] 8e 44 [2] c9 55 [2] 87 59 [2] 8b 53 [2] 9c 58 [2] 87 16 [2] ba }

  condition:
    any of them
}