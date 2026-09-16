rule TTP_XOR_MULT_DOSStub_4523 {
  strings:
    $key_4523 = { 11 4b [2] 65 53 [2] 22 51 [2] 65 40 [2] 2b 4c [2] 27 46 [2] 30 4d [2] 2b 03 [2] 16 }

  condition:
    any of them
}