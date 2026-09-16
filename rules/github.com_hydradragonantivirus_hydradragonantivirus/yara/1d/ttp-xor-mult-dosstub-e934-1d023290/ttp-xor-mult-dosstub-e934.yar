rule TTP_XOR_MULT_DOSStub_e934 {
  strings:
    $key_e934 = { bd 5c [2] c9 44 [2] 8e 46 [2] c9 57 [2] 87 5b [2] 8b 51 [2] 9c 5a [2] 87 14 [2] ba }

  condition:
    any of them
}