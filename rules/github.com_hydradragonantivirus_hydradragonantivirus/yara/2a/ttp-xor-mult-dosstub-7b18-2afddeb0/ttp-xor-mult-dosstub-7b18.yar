rule TTP_XOR_MULT_DOSStub_7b18 {
  strings:
    $key_7b18 = { 2f 70 [2] 5b 68 [2] 1c 6a [2] 5b 7b [2] 15 77 [2] 19 7d [2] 0e 76 [2] 15 38 [2] 28 }

  condition:
    any of them
}