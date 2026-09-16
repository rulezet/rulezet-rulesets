rule TTP_XOR_MULT_DOSStub_e9eb {
  strings:
    $key_e9eb = { bd 83 [2] c9 9b [2] 8e 99 [2] c9 88 [2] 87 84 [2] 8b 8e [2] 9c 85 [2] 87 cb [2] ba }

  condition:
    any of them
}