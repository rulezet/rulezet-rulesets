rule TTP_XOR_MULT_DOSStub_e909 {
  strings:
    $key_e909 = { bd 61 [2] c9 79 [2] 8e 7b [2] c9 6a [2] 87 66 [2] 8b 6c [2] 9c 67 [2] 87 29 [2] ba }

  condition:
    any of them
}