rule TTP_XOR_MULT_DOSStub_2520 {
  strings:
    $key_2520 = { 71 48 [2] 05 50 [2] 42 52 [2] 05 43 [2] 4b 4f [2] 47 45 [2] 50 4e [2] 4b 00 [2] 76 }

  condition:
    any of them
}