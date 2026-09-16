rule TTP_XOR_MULT_DOSStub_370e {
  strings:
    $key_370e = { 63 66 [2] 17 7e [2] 50 7c [2] 17 6d [2] 59 61 [2] 55 6b [2] 42 60 [2] 59 2e [2] 64 }

  condition:
    any of them
}