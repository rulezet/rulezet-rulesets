rule TTP_XOR_MULT_DOSStub_7132 {
  strings:
    $key_7132 = { 25 5a [2] 51 42 [2] 16 40 [2] 51 51 [2] 1f 5d [2] 13 57 [2] 04 5c [2] 1f 12 [2] 22 }

  condition:
    any of them
}