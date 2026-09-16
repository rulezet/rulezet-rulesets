rule TTP_XOR_MULT_DOSStub_1824 {
  strings:
    $key_1824 = { 4c 4c [2] 38 54 [2] 7f 56 [2] 38 47 [2] 76 4b [2] 7a 41 [2] 6d 4a [2] 76 04 [2] 4b }

  condition:
    any of them
}