rule TTP_XOR_MULT_DOSStub_e97b {
  strings:
    $key_e97b = { bd 13 [2] c9 0b [2] 8e 09 [2] c9 18 [2] 87 14 [2] 8b 1e [2] 9c 15 [2] 87 5b [2] ba }

  condition:
    any of them
}