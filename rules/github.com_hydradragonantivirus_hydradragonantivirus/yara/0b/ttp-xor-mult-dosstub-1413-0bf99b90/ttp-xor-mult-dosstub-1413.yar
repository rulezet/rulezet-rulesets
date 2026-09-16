rule TTP_XOR_MULT_DOSStub_1413 {
  strings:
    $key_1413 = { 40 7b [2] 34 63 [2] 73 61 [2] 34 70 [2] 7a 7c [2] 76 76 [2] 61 7d [2] 7a 33 [2] 47 }

  condition:
    any of them
}