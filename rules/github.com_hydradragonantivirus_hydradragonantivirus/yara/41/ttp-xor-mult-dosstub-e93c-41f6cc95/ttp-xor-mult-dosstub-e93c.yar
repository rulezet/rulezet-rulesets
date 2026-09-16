rule TTP_XOR_MULT_DOSStub_e93c {
  strings:
    $key_e93c = { bd 54 [2] c9 4c [2] 8e 4e [2] c9 5f [2] 87 53 [2] 8b 59 [2] 9c 52 [2] 87 1c [2] ba }

  condition:
    any of them
}