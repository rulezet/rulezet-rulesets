rule TTP_XOR_MULT_DOSStub_2439 {
  strings:
    $key_2439 = { 70 51 [2] 04 49 [2] 43 4b [2] 04 5a [2] 4a 56 [2] 46 5c [2] 51 57 [2] 4a 19 [2] 77 }

  condition:
    any of them
}