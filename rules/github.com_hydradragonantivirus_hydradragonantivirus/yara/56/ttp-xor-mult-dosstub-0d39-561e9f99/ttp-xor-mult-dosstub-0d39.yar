rule TTP_XOR_MULT_DOSStub_0d39 {
  strings:
    $key_0d39 = { 59 51 [2] 2d 49 [2] 6a 4b [2] 2d 5a [2] 63 56 [2] 6f 5c [2] 78 57 [2] 63 19 [2] 5e }

  condition:
    any of them
}