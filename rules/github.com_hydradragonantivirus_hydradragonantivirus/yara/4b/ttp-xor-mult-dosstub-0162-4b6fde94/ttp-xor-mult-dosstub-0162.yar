rule TTP_XOR_MULT_DOSStub_0162 {
  strings:
    $key_0162 = { 55 0a [2] 21 12 [2] 66 10 [2] 21 01 [2] 6f 0d [2] 63 07 [2] 74 0c [2] 6f 42 [2] 52 }

  condition:
    any of them
}