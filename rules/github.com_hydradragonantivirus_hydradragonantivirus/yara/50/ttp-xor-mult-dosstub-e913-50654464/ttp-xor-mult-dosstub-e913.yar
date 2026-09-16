rule TTP_XOR_MULT_DOSStub_e913 {
  strings:
    $key_e913 = { bd 7b [2] c9 63 [2] 8e 61 [2] c9 70 [2] 87 7c [2] 8b 76 [2] 9c 7d [2] 87 33 [2] ba }

  condition:
    any of them
}