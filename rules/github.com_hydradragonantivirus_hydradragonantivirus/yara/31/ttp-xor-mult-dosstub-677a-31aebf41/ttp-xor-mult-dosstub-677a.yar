rule TTP_XOR_MULT_DOSStub_677a {
  strings:
    $key_677a = { 33 12 [2] 47 0a [2] 00 08 [2] 47 19 [2] 09 15 [2] 05 1f [2] 12 14 [2] 09 5a [2] 34 }

  condition:
    any of them
}