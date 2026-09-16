rule TTP_XOR_MULT_DOSStub_e941 {
  strings:
    $key_e941 = { bd 29 [2] c9 31 [2] 8e 33 [2] c9 22 [2] 87 2e [2] 8b 24 [2] 9c 2f [2] 87 61 [2] ba }

  condition:
    any of them
}