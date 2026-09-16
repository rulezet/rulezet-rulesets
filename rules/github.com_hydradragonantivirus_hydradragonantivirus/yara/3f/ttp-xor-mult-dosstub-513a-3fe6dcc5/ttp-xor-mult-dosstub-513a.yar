rule TTP_XOR_MULT_DOSStub_513a {
  strings:
    $key_513a = { 05 52 [2] 71 4a [2] 36 48 [2] 71 59 [2] 3f 55 [2] 33 5f [2] 24 54 [2] 3f 1a [2] 02 }

  condition:
    any of them
}