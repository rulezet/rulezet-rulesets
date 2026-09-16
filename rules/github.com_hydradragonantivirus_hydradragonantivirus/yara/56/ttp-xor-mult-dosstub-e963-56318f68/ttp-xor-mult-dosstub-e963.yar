rule TTP_XOR_MULT_DOSStub_e963 {
  strings:
    $key_e963 = { bd 0b [2] c9 13 [2] 8e 11 [2] c9 00 [2] 87 0c [2] 8b 06 [2] 9c 0d [2] 87 43 [2] ba }

  condition:
    any of them
}