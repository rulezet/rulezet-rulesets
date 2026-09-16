rule TTP_XOR_MULT_DOSStub_e96d {
  strings:
    $key_e96d = { bd 05 [2] c9 1d [2] 8e 1f [2] c9 0e [2] 87 02 [2] 8b 08 [2] 9c 03 [2] 87 4d [2] ba }

  condition:
    any of them
}