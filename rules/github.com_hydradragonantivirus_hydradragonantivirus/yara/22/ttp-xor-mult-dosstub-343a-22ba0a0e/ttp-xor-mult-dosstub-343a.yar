rule TTP_XOR_MULT_DOSStub_343a {
  strings:
    $key_343a = { 60 52 [2] 14 4a [2] 53 48 [2] 14 59 [2] 5a 55 [2] 56 5f [2] 41 54 [2] 5a 1a [2] 67 }

  condition:
    any of them
}