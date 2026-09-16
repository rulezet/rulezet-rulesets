rule TTP_XOR_MULT_DOSStub_e9f9 {
  strings:
    $key_e9f9 = { bd 91 [2] c9 89 [2] 8e 8b [2] c9 9a [2] 87 96 [2] 8b 9c [2] 9c 97 [2] 87 d9 [2] ba }

  condition:
    any of them
}