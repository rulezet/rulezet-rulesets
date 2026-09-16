rule TTP_XOR_MULT_DOSStub_2805 {
  strings:
    $key_2805 = { 7c 6d [2] 08 75 [2] 4f 77 [2] 08 66 [2] 46 6a [2] 4a 60 [2] 5d 6b [2] 46 25 [2] 7b }

  condition:
    any of them
}