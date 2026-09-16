rule TTP_XOR_MULT_DOSStub_e978 {
  strings:
    $key_e978 = { bd 10 [2] c9 08 [2] 8e 0a [2] c9 1b [2] 87 17 [2] 8b 1d [2] 9c 16 [2] 87 58 [2] ba }

  condition:
    any of them
}