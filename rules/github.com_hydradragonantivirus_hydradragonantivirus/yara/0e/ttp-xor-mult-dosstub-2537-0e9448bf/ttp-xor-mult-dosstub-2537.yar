rule TTP_XOR_MULT_DOSStub_2537 {
  strings:
    $key_2537 = { 71 5f [2] 05 47 [2] 42 45 [2] 05 54 [2] 4b 58 [2] 47 52 [2] 50 59 [2] 4b 17 [2] 76 }

  condition:
    any of them
}