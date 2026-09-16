rule TTP_XOR_MULT_DOSStub_e969 {
  strings:
    $key_e969 = { bd 01 [2] c9 19 [2] 8e 1b [2] c9 0a [2] 87 06 [2] 8b 0c [2] 9c 07 [2] 87 49 [2] ba }

  condition:
    any of them
}