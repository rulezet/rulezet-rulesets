rule TTP_XOR_MULT_DOSStub_2639 {
  strings:
    $key_2639 = { 72 51 [2] 06 49 [2] 41 4b [2] 06 5a [2] 48 56 [2] 44 5c [2] 53 57 [2] 48 19 [2] 75 }

  condition:
    any of them
}