rule TTP_XOR_MULT_DOSStub_7029 {
  strings:
    $key_7029 = { 24 41 [2] 50 59 [2] 17 5b [2] 50 4a [2] 1e 46 [2] 12 4c [2] 05 47 [2] 1e 09 [2] 23 }

  condition:
    any of them
}