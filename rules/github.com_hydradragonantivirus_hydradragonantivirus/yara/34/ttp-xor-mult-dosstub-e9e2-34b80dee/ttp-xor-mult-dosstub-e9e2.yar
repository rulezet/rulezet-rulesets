rule TTP_XOR_MULT_DOSStub_e9e2 {
  strings:
    $key_e9e2 = { bd 8a [2] c9 92 [2] 8e 90 [2] c9 81 [2] 87 8d [2] 8b 87 [2] 9c 8c [2] 87 c2 [2] ba }

  condition:
    any of them
}