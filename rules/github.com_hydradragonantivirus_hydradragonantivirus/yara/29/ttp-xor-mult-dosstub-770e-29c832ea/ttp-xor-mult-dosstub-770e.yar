rule TTP_XOR_MULT_DOSStub_770e {
  strings:
    $key_770e = { 23 66 [2] 57 7e [2] 10 7c [2] 57 6d [2] 19 61 [2] 15 6b [2] 02 60 [2] 19 2e [2] 24 }

  condition:
    any of them
}