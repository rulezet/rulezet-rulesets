rule TTP_XOR_MULT_DOSStub_7138 {
  strings:
    $key_7138 = { 25 50 [2] 51 48 [2] 16 4a [2] 51 5b [2] 1f 57 [2] 13 5d [2] 04 56 [2] 1f 18 [2] 22 }

  condition:
    any of them
}