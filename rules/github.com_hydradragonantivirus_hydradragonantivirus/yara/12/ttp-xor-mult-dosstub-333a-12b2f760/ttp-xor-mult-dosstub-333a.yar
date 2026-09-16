rule TTP_XOR_MULT_DOSStub_333a {
  strings:
    $key_333a = { 67 52 [2] 13 4a [2] 54 48 [2] 13 59 [2] 5d 55 [2] 51 5f [2] 46 54 [2] 5d 1a [2] 60 }

  condition:
    any of them
}