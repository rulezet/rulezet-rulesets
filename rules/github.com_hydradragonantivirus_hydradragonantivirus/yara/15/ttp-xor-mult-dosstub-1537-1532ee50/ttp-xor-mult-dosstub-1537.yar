rule TTP_XOR_MULT_DOSStub_1537 {
  strings:
    $key_1537 = { 41 5f [2] 35 47 [2] 72 45 [2] 35 54 [2] 7b 58 [2] 77 52 [2] 60 59 [2] 7b 17 [2] 46 }

  condition:
    any of them
}