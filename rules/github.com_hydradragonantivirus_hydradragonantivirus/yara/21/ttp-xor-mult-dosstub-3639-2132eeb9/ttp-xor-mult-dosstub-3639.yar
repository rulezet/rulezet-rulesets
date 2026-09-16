rule TTP_XOR_MULT_DOSStub_3639 {
  strings:
    $key_3639 = { 62 51 [2] 16 49 [2] 51 4b [2] 16 5a [2] 58 56 [2] 54 5c [2] 43 57 [2] 58 19 [2] 65 }

  condition:
    any of them
}