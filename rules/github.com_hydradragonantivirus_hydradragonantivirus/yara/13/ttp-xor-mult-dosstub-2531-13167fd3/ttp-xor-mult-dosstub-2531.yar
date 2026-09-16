rule TTP_XOR_MULT_DOSStub_2531 {
  strings:
    $key_2531 = { 71 59 [2] 05 41 [2] 42 43 [2] 05 52 [2] 4b 5e [2] 47 54 [2] 50 5f [2] 4b 11 [2] 76 }

  condition:
    any of them
}