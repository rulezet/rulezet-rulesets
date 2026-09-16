rule TTP_XOR_MULT_DOSStub_5523 {
  strings:
    $key_5523 = { 01 4b [2] 75 53 [2] 32 51 [2] 75 40 [2] 3b 4c [2] 37 46 [2] 20 4d [2] 3b 03 [2] 06 }

  condition:
    any of them
}