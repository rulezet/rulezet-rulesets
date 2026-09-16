rule TTP_XOR_MULT_DOSStub_2423 {
  strings:
    $key_2423 = { 70 4b [2] 04 53 [2] 43 51 [2] 04 40 [2] 4a 4c [2] 46 46 [2] 51 4d [2] 4a 03 [2] 77 }

  condition:
    any of them
}