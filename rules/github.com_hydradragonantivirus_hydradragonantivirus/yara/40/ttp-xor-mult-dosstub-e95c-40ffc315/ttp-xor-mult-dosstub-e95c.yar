rule TTP_XOR_MULT_DOSStub_e95c {
  strings:
    $key_e95c = { bd 34 [2] c9 2c [2] 8e 2e [2] c9 3f [2] 87 33 [2] 8b 39 [2] 9c 32 [2] 87 7c [2] ba }

  condition:
    any of them
}