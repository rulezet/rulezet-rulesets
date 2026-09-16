rule TTP_XOR_MULT_DOSStub_5628 {
  strings:
    $key_5628 = { 02 40 [2] 76 58 [2] 31 5a [2] 76 4b [2] 38 47 [2] 34 4d [2] 23 46 [2] 38 08 [2] 05 }

  condition:
    any of them
}