rule TTP_XOR_MULT_DOSStub_e945 {
  strings:
    $key_e945 = { bd 2d [2] c9 35 [2] 8e 37 [2] c9 26 [2] 87 2a [2] 8b 20 [2] 9c 2b [2] 87 65 [2] ba }

  condition:
    any of them
}