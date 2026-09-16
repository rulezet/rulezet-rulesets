rule TTP_XOR_MULT_DOSStub_3462 {
  strings:
    $key_3462 = { 60 0a [2] 14 12 [2] 53 10 [2] 14 01 [2] 5a 0d [2] 56 07 [2] 41 0c [2] 5a 42 [2] 67 }

  condition:
    any of them
}