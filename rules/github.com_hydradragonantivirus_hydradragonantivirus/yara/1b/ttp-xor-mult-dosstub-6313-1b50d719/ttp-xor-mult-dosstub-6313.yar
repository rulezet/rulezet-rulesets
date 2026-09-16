rule TTP_XOR_MULT_DOSStub_6313 {
  strings:
    $key_6313 = { 37 7b [2] 43 63 [2] 04 61 [2] 43 70 [2] 0d 7c [2] 01 76 [2] 16 7d [2] 0d 33 [2] 30 }

  condition:
    any of them
}