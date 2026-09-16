rule TTP_XOR_MULT_DOSStub_2838 {
  strings:
    $key_2838 = { 7c 50 [2] 08 48 [2] 4f 4a [2] 08 5b [2] 46 57 [2] 4a 5d [2] 5d 56 [2] 46 18 [2] 7b }

  condition:
    any of them
}