rule TTP_XOR_MULT_DOSStub_e9f5 {
  strings:
    $key_e9f5 = { bd 9d [2] c9 85 [2] 8e 87 [2] c9 96 [2] 87 9a [2] 8b 90 [2] 9c 9b [2] 87 d5 [2] ba }

  condition:
    any of them
}