rule TTP_XOR_MULT_DOSStub_5e37 {
  strings:
    $key_5e37 = { 0a 5f [2] 7e 47 [2] 39 45 [2] 7e 54 [2] 30 58 [2] 3c 52 [2] 2b 59 [2] 30 17 [2] 0d }

  condition:
    any of them
}