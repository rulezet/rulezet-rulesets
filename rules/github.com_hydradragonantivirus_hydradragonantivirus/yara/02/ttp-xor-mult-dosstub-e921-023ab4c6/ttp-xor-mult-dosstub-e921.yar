rule TTP_XOR_MULT_DOSStub_e921 {
  strings:
    $key_e921 = { bd 49 [2] c9 51 [2] 8e 53 [2] c9 42 [2] 87 4e [2] 8b 44 [2] 9c 4f [2] 87 01 [2] ba }

  condition:
    any of them
}