rule TTP_XOR_MULT_DOSStub_577a {
  strings:
    $key_577a = { 03 12 [2] 77 0a [2] 30 08 [2] 77 19 [2] 39 15 [2] 35 1f [2] 22 14 [2] 39 5a [2] 04 }

  condition:
    any of them
}