rule TTP_XOR_MULT_DOSStub_e908 {
  strings:
    $key_e908 = { bd 60 [2] c9 78 [2] 8e 7a [2] c9 6b [2] 87 67 [2] 8b 6d [2] 9c 66 [2] 87 28 [2] ba }

  condition:
    any of them
}