rule TTP_XOR_MULT_DOSStub_0529 {
  strings:
    $key_0529 = { 51 41 [2] 25 59 [2] 62 5b [2] 25 4a [2] 6b 46 [2] 67 4c [2] 70 47 [2] 6b 09 [2] 56 }

  condition:
    any of them
}