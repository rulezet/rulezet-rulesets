rule TTP_XOR_MULT_DOSStub_6850 {
  strings:
    $key_6850 = { 3c 38 [2] 48 20 [2] 0f 22 [2] 48 33 [2] 06 3f [2] 0a 35 [2] 1d 3e [2] 06 70 [2] 3b }

  condition:
    any of them
}