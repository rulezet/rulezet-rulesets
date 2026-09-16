rule TTP_XOR_MULT_DOSStub_670e {
  strings:
    $key_670e = { 33 66 [2] 47 7e [2] 00 7c [2] 47 6d [2] 09 61 [2] 05 6b [2] 12 60 [2] 09 2e [2] 34 }

  condition:
    any of them
}