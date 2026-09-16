rule TTP_XOR_MULT_DOSStub_1813 {
  strings:
    $key_1813 = { 4c 7b [2] 38 63 [2] 7f 61 [2] 38 70 [2] 76 7c [2] 7a 76 [2] 6d 7d [2] 76 33 [2] 4b }

  condition:
    any of them
}