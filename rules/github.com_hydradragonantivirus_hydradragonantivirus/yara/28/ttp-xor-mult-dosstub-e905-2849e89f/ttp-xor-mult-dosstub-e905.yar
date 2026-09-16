rule TTP_XOR_MULT_DOSStub_e905 {
  strings:
    $key_e905 = { bd 6d [2] c9 75 [2] 8e 77 [2] c9 66 [2] 87 6a [2] 8b 60 [2] 9c 6b [2] 87 25 [2] ba }

  condition:
    any of them
}