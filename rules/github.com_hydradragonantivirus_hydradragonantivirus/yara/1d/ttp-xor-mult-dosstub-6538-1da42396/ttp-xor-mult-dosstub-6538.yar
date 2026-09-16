rule TTP_XOR_MULT_DOSStub_6538 {
  strings:
    $key_6538 = { 31 50 [2] 45 48 [2] 02 4a [2] 45 5b [2] 0b 57 [2] 07 5d [2] 10 56 [2] 0b 18 [2] 36 }

  condition:
    any of them
}