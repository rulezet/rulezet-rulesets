rule TTP_XOR_MULT_DOSStub_2732 {
  strings:
    $key_2732 = { 73 5a [2] 07 42 [2] 40 40 [2] 07 51 [2] 49 5d [2] 45 57 [2] 52 5c [2] 49 12 [2] 74 }

  condition:
    any of them
}