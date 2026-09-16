rule TTP_XOR_MULT_DOSStub_e900 {
  strings:
    $key_e900 = { bd 68 [2] c9 70 [2] 8e 72 [2] c9 63 [2] 87 6f [2] 8b 65 [2] 9c 6e [2] 87 20 [2] ba }

  condition:
    any of them
}