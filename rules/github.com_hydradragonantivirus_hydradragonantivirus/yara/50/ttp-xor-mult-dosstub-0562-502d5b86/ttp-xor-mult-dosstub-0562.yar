rule TTP_XOR_MULT_DOSStub_0562 {
  strings:
    $key_0562 = { 51 0a [2] 25 12 [2] 62 10 [2] 25 01 [2] 6b 0d [2] 67 07 [2] 70 0c [2] 6b 42 [2] 56 }

  condition:
    any of them
}