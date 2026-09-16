rule TTP_XOR_MULT_DOSStub_573a {
  strings:
    $key_573a = { 03 52 [2] 77 4a [2] 30 48 [2] 77 59 [2] 39 55 [2] 35 5f [2] 22 54 [2] 39 1a [2] 04 }

  condition:
    any of them
}