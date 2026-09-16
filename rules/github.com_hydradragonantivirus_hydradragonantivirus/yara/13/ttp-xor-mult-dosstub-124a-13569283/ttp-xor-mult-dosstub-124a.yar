rule TTP_XOR_MULT_DOSStub_124a {
  strings:
    $key_124a = { 46 22 [2] 32 3a [2] 75 38 [2] 32 29 [2] 7c 25 [2] 70 2f [2] 67 24 [2] 7c 6a [2] 41 }

  condition:
    any of them
}