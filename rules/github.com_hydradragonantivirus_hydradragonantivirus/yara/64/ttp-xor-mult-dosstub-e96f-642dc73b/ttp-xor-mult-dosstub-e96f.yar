rule TTP_XOR_MULT_DOSStub_e96f {
  strings:
    $key_e96f = { bd 07 [2] c9 1f [2] 8e 1d [2] c9 0c [2] 87 00 [2] 8b 0a [2] 9c 01 [2] 87 4f [2] ba }

  condition:
    any of them
}