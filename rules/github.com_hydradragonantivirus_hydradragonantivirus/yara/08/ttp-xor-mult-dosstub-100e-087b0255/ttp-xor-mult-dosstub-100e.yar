rule TTP_XOR_MULT_DOSStub_100e {
  strings:
    $key_100e = { 44 66 [2] 30 7e [2] 77 7c [2] 30 6d [2] 7e 61 [2] 72 6b [2] 65 60 [2] 7e 2e [2] 43 }

  condition:
    any of them
}