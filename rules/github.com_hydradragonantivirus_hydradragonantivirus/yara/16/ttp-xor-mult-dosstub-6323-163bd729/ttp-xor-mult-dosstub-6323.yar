rule TTP_XOR_MULT_DOSStub_6323 {
  strings:
    $key_6323 = { 37 4b [2] 43 53 [2] 04 51 [2] 43 40 [2] 0d 4c [2] 01 46 [2] 16 4d [2] 0d 03 [2] 30 }

  condition:
    any of them
}