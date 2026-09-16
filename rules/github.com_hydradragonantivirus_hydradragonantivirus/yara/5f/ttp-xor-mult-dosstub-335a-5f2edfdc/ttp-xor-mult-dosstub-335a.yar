rule TTP_XOR_MULT_DOSStub_335a {
  strings:
    $key_335a = { 67 32 [2] 13 2a [2] 54 28 [2] 13 39 [2] 5d 35 [2] 51 3f [2] 46 34 [2] 5d 7a [2] 60 }

  condition:
    any of them
}