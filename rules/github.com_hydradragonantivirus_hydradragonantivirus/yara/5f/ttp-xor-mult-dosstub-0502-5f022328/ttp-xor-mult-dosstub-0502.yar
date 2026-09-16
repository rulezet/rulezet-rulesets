rule TTP_XOR_MULT_DOSStub_0502 {
  strings:
    $key_0502 = { 51 6a [2] 25 72 [2] 62 70 [2] 25 61 [2] 6b 6d [2] 67 67 [2] 70 6c [2] 6b 22 [2] 56 }

  condition:
    any of them
}