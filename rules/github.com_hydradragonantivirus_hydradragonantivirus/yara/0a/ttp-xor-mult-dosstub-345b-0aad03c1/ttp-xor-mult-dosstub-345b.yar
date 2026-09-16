rule TTP_XOR_MULT_DOSStub_345b {
  strings:
    $key_345b = { 60 33 [2] 14 2b [2] 53 29 [2] 14 38 [2] 5a 34 [2] 56 3e [2] 41 35 [2] 5a 7b [2] 67 }

  condition:
    any of them
}