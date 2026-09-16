rule TTP_XOR_MULT_DOSStub_5725 {
  strings:
    $key_5725 = { 03 4d [2] 77 55 [2] 30 57 [2] 77 46 [2] 39 4a [2] 35 40 [2] 22 4b [2] 39 05 [2] 04 }

  condition:
    any of them
}