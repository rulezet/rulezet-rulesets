rule TTP_XOR_MULT_DOSStub_e915 {
  strings:
    $key_e915 = { bd 7d [2] c9 65 [2] 8e 67 [2] c9 76 [2] 87 7a [2] 8b 70 [2] 9c 7b [2] 87 35 [2] ba }

  condition:
    any of them
}