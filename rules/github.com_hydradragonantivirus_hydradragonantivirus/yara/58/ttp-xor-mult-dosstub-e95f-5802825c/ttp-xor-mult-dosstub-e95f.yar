rule TTP_XOR_MULT_DOSStub_e95f {
  strings:
    $key_e95f = { bd 37 [2] c9 2f [2] 8e 2d [2] c9 3c [2] 87 30 [2] 8b 3a [2] 9c 31 [2] 87 7f [2] ba }

  condition:
    any of them
}