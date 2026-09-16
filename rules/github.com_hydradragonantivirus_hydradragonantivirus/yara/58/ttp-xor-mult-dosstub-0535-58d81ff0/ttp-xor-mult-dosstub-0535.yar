rule TTP_XOR_MULT_DOSStub_0535 {
  strings:
    $key_0535 = { 51 5d [2] 25 45 [2] 62 47 [2] 25 56 [2] 6b 5a [2] 67 50 [2] 70 5b [2] 6b 15 [2] 56 }

  condition:
    any of them
}