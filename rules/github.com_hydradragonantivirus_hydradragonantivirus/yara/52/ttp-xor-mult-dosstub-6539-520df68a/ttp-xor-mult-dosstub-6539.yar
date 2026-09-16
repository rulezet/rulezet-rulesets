rule TTP_XOR_MULT_DOSStub_6539 {
  strings:
    $key_6539 = { 31 51 [2] 45 49 [2] 02 4b [2] 45 5a [2] 0b 56 [2] 07 5c [2] 10 57 [2] 0b 19 [2] 36 }

  condition:
    any of them
}