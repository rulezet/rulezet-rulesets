rule TTP_XOR_MULT_DOSStub_040e {
  strings:
    $key_040e = { 50 66 [2] 24 7e [2] 63 7c [2] 24 6d [2] 6a 61 [2] 66 6b [2] 71 60 [2] 6a 2e [2] 57 }

  condition:
    any of them
}