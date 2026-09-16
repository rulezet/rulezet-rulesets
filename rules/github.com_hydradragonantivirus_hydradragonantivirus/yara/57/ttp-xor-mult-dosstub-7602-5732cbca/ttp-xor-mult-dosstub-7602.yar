rule TTP_XOR_MULT_DOSStub_7602 {
  strings:
    $key_7602 = { 22 6a [2] 56 72 [2] 11 70 [2] 56 61 [2] 18 6d [2] 14 67 [2] 03 6c [2] 18 22 [2] 25 }

  condition:
    any of them
}