rule TTP_XOR_MULT_DOSStub_2857 {
  strings:
    $key_2857 = { 7c 3f [2] 08 27 [2] 4f 25 [2] 08 34 [2] 46 38 [2] 4a 32 [2] 5d 39 [2] 46 77 [2] 7b }

  condition:
    any of them
}