rule TTP_XOR_MULT_DOSStub_5d27 {
  strings:
    $key_5d27 = { 09 4f [2] 7d 57 [2] 3a 55 [2] 7d 44 [2] 33 48 [2] 3f 42 [2] 28 49 [2] 33 07 [2] 0e }

  condition:
    any of them
}