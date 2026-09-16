rule TTP_XOR_MULT_DOSStub_0138 {
  strings:
    $key_0138 = { 55 50 [2] 21 48 [2] 66 4a [2] 21 5b [2] 6f 57 [2] 63 5d [2] 74 56 [2] 6f 18 [2] 52 }

  condition:
    any of them
}