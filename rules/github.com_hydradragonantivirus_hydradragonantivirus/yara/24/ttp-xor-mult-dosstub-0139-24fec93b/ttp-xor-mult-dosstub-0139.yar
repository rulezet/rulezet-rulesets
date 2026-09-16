rule TTP_XOR_MULT_DOSStub_0139 {
  strings:
    $key_0139 = { 55 51 [2] 21 49 [2] 66 4b [2] 21 5a [2] 6f 56 [2] 63 5c [2] 74 57 [2] 6f 19 [2] 52 }

  condition:
    any of them
}