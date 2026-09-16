rule TTP_XOR_MULT_DOSStub_3034 {
  strings:
    $key_3034 = { 64 5c [2] 10 44 [2] 57 46 [2] 10 57 [2] 5e 5b [2] 52 51 [2] 45 5a [2] 5e 14 [2] 63 }

  condition:
    any of them
}