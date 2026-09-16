rule TTP_XOR_MULT_DOSStub_0002 {
  strings:
    $key_0002 = { 54 6a [2] 20 72 [2] 67 70 [2] 20 61 [2] 6e 6d [2] 62 67 [2] 75 6c [2] 6e 22 [2] 53 }

  condition:
    any of them
}