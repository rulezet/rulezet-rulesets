rule TTP_XOR_MULT_DOSStub_247a {
  strings:
    $key_247a = { 70 12 [2] 04 0a [2] 43 08 [2] 04 19 [2] 4a 15 [2] 46 1f [2] 51 14 [2] 4a 5a [2] 77 }

  condition:
    any of them
}