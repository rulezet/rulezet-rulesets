rule TTP_XOR_MULT_DOSStub_e931 {
  strings:
    $key_e931 = { bd 59 [2] c9 41 [2] 8e 43 [2] c9 52 [2] 87 5e [2] 8b 54 [2] 9c 5f [2] 87 11 [2] ba }

  condition:
    any of them
}