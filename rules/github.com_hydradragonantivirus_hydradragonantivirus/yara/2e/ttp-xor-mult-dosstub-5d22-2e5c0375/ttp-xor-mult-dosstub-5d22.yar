rule TTP_XOR_MULT_DOSStub_5d22 {
  strings:
    $key_5d22 = { 09 4a [2] 7d 52 [2] 3a 50 [2] 7d 41 [2] 33 4d [2] 3f 47 [2] 28 4c [2] 33 02 [2] 0e }

  condition:
    any of them
}