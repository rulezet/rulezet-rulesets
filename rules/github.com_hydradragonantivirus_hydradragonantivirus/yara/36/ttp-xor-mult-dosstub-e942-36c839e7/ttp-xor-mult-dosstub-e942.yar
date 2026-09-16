rule TTP_XOR_MULT_DOSStub_e942 {
  strings:
    $key_e942 = { bd 2a [2] c9 32 [2] 8e 30 [2] c9 21 [2] 87 2d [2] 8b 27 [2] 9c 2c [2] 87 62 [2] ba }

  condition:
    any of them
}