rule TTP_XOR_MULT_DOSStub_0533 {
  strings:
    $key_0533 = { 51 5b [2] 25 43 [2] 62 41 [2] 25 50 [2] 6b 5c [2] 67 56 [2] 70 5d [2] 6b 13 [2] 56 }

  condition:
    any of them
}