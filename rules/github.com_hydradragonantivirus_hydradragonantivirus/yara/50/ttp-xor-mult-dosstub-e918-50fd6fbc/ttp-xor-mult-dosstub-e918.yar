rule TTP_XOR_MULT_DOSStub_e918 {
  strings:
    $key_e918 = { bd 70 [2] c9 68 [2] 8e 6a [2] c9 7b [2] 87 77 [2] 8b 7d [2] 9c 76 [2] 87 38 [2] ba }

  condition:
    any of them
}