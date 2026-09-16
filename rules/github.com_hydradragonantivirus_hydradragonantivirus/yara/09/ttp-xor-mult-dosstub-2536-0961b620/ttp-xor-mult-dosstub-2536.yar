rule TTP_XOR_MULT_DOSStub_2536 {
  strings:
    $key_2536 = { 71 5e [2] 05 46 [2] 42 44 [2] 05 55 [2] 4b 59 [2] 47 53 [2] 50 58 [2] 4b 16 [2] 76 }

  condition:
    any of them
}