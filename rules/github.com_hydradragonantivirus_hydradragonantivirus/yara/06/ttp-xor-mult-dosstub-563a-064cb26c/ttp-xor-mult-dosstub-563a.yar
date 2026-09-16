rule TTP_XOR_MULT_DOSStub_563a {
  strings:
    $key_563a = { 02 52 [2] 76 4a [2] 31 48 [2] 76 59 [2] 38 55 [2] 34 5f [2] 23 54 [2] 38 1a [2] 05 }

  condition:
    any of them
}