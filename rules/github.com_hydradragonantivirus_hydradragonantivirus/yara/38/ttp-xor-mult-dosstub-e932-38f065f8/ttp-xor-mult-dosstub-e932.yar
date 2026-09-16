rule TTP_XOR_MULT_DOSStub_e932 {
  strings:
    $key_e932 = { bd 5a [2] c9 42 [2] 8e 40 [2] c9 51 [2] 87 5d [2] 8b 57 [2] 9c 5c [2] 87 12 [2] ba }

  condition:
    any of them
}