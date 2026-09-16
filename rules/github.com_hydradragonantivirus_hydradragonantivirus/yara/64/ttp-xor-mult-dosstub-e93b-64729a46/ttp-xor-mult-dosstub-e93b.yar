rule TTP_XOR_MULT_DOSStub_e93b {
  strings:
    $key_e93b = { bd 53 [2] c9 4b [2] 8e 49 [2] c9 58 [2] 87 54 [2] 8b 5e [2] 9c 55 [2] 87 1b [2] ba }

  condition:
    any of them
}