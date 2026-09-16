rule TTP_XOR_MULT_DOSStub_e9f1 {
  strings:
    $key_e9f1 = { bd 99 [2] c9 81 [2] 8e 83 [2] c9 92 [2] 87 9e [2] 8b 94 [2] 9c 9f [2] 87 d1 [2] ba }

  condition:
    any of them
}