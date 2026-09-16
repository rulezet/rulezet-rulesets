rule TTP_XOR_MULT_DOSStub_e234 {
  strings:
    $key_e234 = { b6 5c [2] c2 44 [2] 85 46 [2] c2 57 [2] 8c 5b [2] 80 51 [2] 97 5a [2] 8c 14 [2] b1 }

  condition:
    any of them
}