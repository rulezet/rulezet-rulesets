rule TTP_XOR_MULT_DOSStub_e950 {
  strings:
    $key_e950 = { bd 38 [2] c9 20 [2] 8e 22 [2] c9 33 [2] 87 3f [2] 8b 35 [2] 9c 3e [2] 87 70 [2] ba }

  condition:
    any of them
}