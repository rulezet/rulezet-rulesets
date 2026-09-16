rule TTP_XOR_MULT_DOSStub_0413 {
  strings:
    $key_0413 = { 50 7b [2] 24 63 [2] 63 61 [2] 24 70 [2] 6a 7c [2] 66 76 [2] 71 7d [2] 6a 33 [2] 57 }

  condition:
    any of them
}