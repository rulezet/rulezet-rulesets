rule TTP_XOR_MULT_DOSStub_233a {
  strings:
    $key_233a = { 77 52 [2] 03 4a [2] 44 48 [2] 03 59 [2] 4d 55 [2] 41 5f [2] 56 54 [2] 4d 1a [2] 70 }

  condition:
    any of them
}