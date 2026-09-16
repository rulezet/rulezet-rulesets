rule TTP_XOR_MULT_DOSStub_e9e6 {
  strings:
    $key_e9e6 = { bd 8e [2] c9 96 [2] 8e 94 [2] c9 85 [2] 87 89 [2] 8b 83 [2] 9c 88 [2] 87 c6 [2] ba }

  condition:
    any of them
}