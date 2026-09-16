rule TTP_XOR_MULT_DOSStub_7232 {
  strings:
    $key_7232 = { 26 5a [2] 52 42 [2] 15 40 [2] 52 51 [2] 1c 5d [2] 10 57 [2] 07 5c [2] 1c 12 [2] 21 }

  condition:
    any of them
}