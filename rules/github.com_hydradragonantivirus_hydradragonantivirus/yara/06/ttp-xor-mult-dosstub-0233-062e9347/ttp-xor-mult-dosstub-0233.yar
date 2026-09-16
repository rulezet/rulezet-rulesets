rule TTP_XOR_MULT_DOSStub_0233 {
  strings:
    $key_0233 = { 56 5b [2] 22 43 [2] 65 41 [2] 22 50 [2] 6c 5c [2] 60 56 [2] 77 5d [2] 6c 13 [2] 51 }

  condition:
    any of them
}