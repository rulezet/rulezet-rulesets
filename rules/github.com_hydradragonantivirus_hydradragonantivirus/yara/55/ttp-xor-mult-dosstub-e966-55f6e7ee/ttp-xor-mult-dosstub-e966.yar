rule TTP_XOR_MULT_DOSStub_e966 {
  strings:
    $key_e966 = { bd 0e [2] c9 16 [2] 8e 14 [2] c9 05 [2] 87 09 [2] 8b 03 [2] 9c 08 [2] 87 46 [2] ba }

  condition:
    any of them
}