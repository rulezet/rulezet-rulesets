rule TTP_XOR_MULT_DOSStub_633a {
  strings:
    $key_633a = { 37 52 [2] 43 4a [2] 04 48 [2] 43 59 [2] 0d 55 [2] 01 5f [2] 16 54 [2] 0d 1a [2] 30 }

  condition:
    any of them
}