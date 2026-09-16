rule TTP_XOR_MULT_DOSStub_3513 {
  strings:
    $key_3513 = { 61 7b [2] 15 63 [2] 52 61 [2] 15 70 [2] 5b 7c [2] 57 76 [2] 40 7d [2] 5b 33 [2] 66 }

  condition:
    any of them
}