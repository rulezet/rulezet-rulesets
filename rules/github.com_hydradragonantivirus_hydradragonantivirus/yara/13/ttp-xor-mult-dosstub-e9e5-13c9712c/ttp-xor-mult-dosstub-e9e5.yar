rule TTP_XOR_MULT_DOSStub_e9e5 {
  strings:
    $key_e9e5 = { bd 8d [2] c9 95 [2] 8e 97 [2] c9 86 [2] 87 8a [2] 8b 80 [2] 9c 8b [2] 87 c5 [2] ba }

  condition:
    any of them
}