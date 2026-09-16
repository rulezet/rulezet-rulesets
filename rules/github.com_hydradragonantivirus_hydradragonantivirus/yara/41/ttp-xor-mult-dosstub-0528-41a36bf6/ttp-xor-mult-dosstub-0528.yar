rule TTP_XOR_MULT_DOSStub_0528 {
  strings:
    $key_0528 = { 51 40 [2] 25 58 [2] 62 5a [2] 25 4b [2] 6b 47 [2] 67 4d [2] 70 46 [2] 6b 08 [2] 56 }

  condition:
    any of them
}