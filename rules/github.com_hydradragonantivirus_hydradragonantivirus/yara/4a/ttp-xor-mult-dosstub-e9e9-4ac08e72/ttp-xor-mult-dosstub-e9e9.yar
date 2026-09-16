rule TTP_XOR_MULT_DOSStub_e9e9 {
  strings:
    $key_e9e9 = { bd 81 [2] c9 99 [2] 8e 9b [2] c9 8a [2] 87 86 [2] 8b 8c [2] 9c 87 [2] 87 c9 [2] ba }

  condition:
    any of them
}