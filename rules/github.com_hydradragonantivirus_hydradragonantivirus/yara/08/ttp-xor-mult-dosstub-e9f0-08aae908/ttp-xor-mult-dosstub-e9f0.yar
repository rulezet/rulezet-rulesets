rule TTP_XOR_MULT_DOSStub_e9f0 {
  strings:
    $key_e9f0 = { bd 98 [2] c9 80 [2] 8e 82 [2] c9 93 [2] 87 9f [2] 8b 95 [2] 9c 9e [2] 87 d0 [2] ba }

  condition:
    any of them
}