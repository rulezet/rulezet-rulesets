rule TTP_XOR_MULT_DOSStub_e961 {
  strings:
    $key_e961 = { bd 09 [2] c9 11 [2] 8e 13 [2] c9 02 [2] 87 0e [2] 8b 04 [2] 9c 0f [2] 87 41 [2] ba }

  condition:
    any of them
}