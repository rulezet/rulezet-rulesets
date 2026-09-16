rule TTP_XOR_MULT_DOSStub_2409 {
  strings:
    $key_2409 = { 70 61 [2] 04 79 [2] 43 7b [2] 04 6a [2] 4a 66 [2] 46 6c [2] 51 67 [2] 4a 29 [2] 77 }

  condition:
    any of them
}