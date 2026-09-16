rule TTP_XOR_MULT_DOSStub_2835 {
  strings:
    $key_2835 = { 7c 5d [2] 08 45 [2] 4f 47 [2] 08 56 [2] 46 5a [2] 4a 50 [2] 5d 5b [2] 46 15 [2] 7b }

  condition:
    any of them
}