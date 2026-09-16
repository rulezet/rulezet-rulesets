rule TTP_XOR_MULT_DOSStub_323a {
  strings:
    $key_323a = { 66 52 [2] 12 4a [2] 55 48 [2] 12 59 [2] 5c 55 [2] 50 5f [2] 47 54 [2] 5c 1a [2] 61 }

  condition:
    any of them
}