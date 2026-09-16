rule TTP_XOR_MULT_DOSStub_e96e {
  strings:
    $key_e96e = { bd 06 [2] c9 1e [2] 8e 1c [2] c9 0d [2] 87 01 [2] 8b 0b [2] 9c 00 [2] 87 4e [2] ba }

  condition:
    any of them
}