rule TTP_XOR_MULT_DOSStub_0033 {
  strings:
    $key_0033 = { 54 5b [2] 20 43 [2] 67 41 [2] 20 50 [2] 6e 5c [2] 62 56 [2] 75 5d [2] 6e 13 [2] 53 }

  condition:
    any of them
}