rule TTP_XOR_MULT_DOSStub_e967 {
  strings:
    $key_e967 = { bd 0f [2] c9 17 [2] 8e 15 [2] c9 04 [2] 87 08 [2] 8b 02 [2] 9c 09 [2] 87 47 [2] ba }

  condition:
    any of them
}