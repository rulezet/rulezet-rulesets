rule TTP_XOR_MULT_DOSStub_e928 {
  strings:
    $key_e928 = { bd 40 [2] c9 58 [2] 8e 5a [2] c9 4b [2] 87 47 [2] 8b 4d [2] 9c 46 [2] 87 08 [2] ba }

  condition:
    any of them
}