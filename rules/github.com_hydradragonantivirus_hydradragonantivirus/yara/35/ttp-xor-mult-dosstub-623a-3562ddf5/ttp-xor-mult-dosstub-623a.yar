rule TTP_XOR_MULT_DOSStub_623a {
  strings:
    $key_623a = { 36 52 [2] 42 4a [2] 05 48 [2] 42 59 [2] 0c 55 [2] 00 5f [2] 17 54 [2] 0c 1a [2] 31 }

  condition:
    any of them
}