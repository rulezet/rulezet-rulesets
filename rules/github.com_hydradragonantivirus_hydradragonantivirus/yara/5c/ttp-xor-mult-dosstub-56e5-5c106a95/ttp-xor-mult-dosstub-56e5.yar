rule TTP_XOR_MULT_DOSStub_56e5 {
  strings:
    $key_56e5 = { 02 8d [2] 76 95 [2] 31 97 [2] 76 86 [2] 38 8a [2] 34 80 [2] 23 8b [2] 38 c5 [2] 05 }

  condition:
    any of them
}