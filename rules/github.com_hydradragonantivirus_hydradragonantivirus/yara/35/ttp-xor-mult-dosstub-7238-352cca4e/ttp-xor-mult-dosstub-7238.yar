rule TTP_XOR_MULT_DOSStub_7238 {
  strings:
    $key_7238 = { 26 50 [2] 52 48 [2] 15 4a [2] 52 5b [2] 1c 57 [2] 10 5d [2] 07 56 [2] 1c 18 [2] 21 }

  condition:
    any of them
}