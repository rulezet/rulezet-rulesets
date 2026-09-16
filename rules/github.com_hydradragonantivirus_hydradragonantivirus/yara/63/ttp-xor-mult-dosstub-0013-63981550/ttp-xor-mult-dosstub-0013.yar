rule TTP_XOR_MULT_DOSStub_0013 {
  strings:
    $key_0013 = { 54 7b [2] 20 63 [2] 67 61 [2] 20 70 [2] 6e 7c [2] 62 76 [2] 75 7d [2] 6e 33 [2] 53 }

  condition:
    any of them
}