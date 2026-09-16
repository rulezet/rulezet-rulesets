rule TTP_XOR_MULT_DOSStub_e944 {
  strings:
    $key_e944 = { bd 2c [2] c9 34 [2] 8e 36 [2] c9 27 [2] 87 2b [2] 8b 21 [2] 9c 2a [2] 87 64 [2] ba }

  condition:
    any of them
}