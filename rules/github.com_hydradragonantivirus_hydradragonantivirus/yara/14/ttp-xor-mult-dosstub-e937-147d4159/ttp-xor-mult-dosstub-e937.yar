rule TTP_XOR_MULT_DOSStub_e937 {
  strings:
    $key_e937 = { bd 5f [2] c9 47 [2] 8e 45 [2] c9 54 [2] 87 58 [2] 8b 52 [2] 9c 59 [2] 87 17 [2] ba }

  condition:
    any of them
}