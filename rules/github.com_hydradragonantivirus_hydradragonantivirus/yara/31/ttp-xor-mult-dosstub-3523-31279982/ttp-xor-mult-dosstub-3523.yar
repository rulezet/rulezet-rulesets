rule TTP_XOR_MULT_DOSStub_3523 {
  strings:
    $key_3523 = { 61 4b [2] 15 53 [2] 52 51 [2] 15 40 [2] 5b 4c [2] 57 46 [2] 40 4d [2] 5b 03 [2] 66 }

  condition:
    any of them
}