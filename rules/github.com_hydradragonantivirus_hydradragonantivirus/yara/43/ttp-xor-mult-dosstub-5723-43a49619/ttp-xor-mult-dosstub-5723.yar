rule TTP_XOR_MULT_DOSStub_5723 {
  strings:
    $key_5723 = { 03 4b [2] 77 53 [2] 30 51 [2] 77 40 [2] 39 4c [2] 35 46 [2] 22 4d [2] 39 03 [2] 04 }

  condition:
    any of them
}