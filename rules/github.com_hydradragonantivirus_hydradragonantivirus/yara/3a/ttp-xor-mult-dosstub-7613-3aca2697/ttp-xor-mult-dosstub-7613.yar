rule TTP_XOR_MULT_DOSStub_7613 {
  strings:
    $key_7613 = { 22 7b [2] 56 63 [2] 11 61 [2] 56 70 [2] 18 7c [2] 14 76 [2] 03 7d [2] 18 33 [2] 25 }

  condition:
    any of them
}