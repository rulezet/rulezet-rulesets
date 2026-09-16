rule TTP_XOR_MULT_DOSStub_025a {
  strings:
    $key_025a = { 56 32 [2] 22 2a [2] 65 28 [2] 22 39 [2] 6c 35 [2] 60 3f [2] 77 34 [2] 6c 7a [2] 51 }

  condition:
    any of them
}