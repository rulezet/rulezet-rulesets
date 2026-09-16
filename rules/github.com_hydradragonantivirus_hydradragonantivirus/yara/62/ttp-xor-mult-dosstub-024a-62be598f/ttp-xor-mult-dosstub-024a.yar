rule TTP_XOR_MULT_DOSStub_024a {
  strings:
    $key_024a = { 56 22 [2] 22 3a [2] 65 38 [2] 22 29 [2] 6c 25 [2] 60 2f [2] 77 24 [2] 6c 6a [2] 51 }

  condition:
    any of them
}