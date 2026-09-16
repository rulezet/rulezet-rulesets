rule TTP_XOR_MULT_DOSStub_450e {
  strings:
    $key_450e = { 11 66 [2] 65 7e [2] 22 7c [2] 65 6d [2] 2b 61 [2] 27 6b [2] 30 60 [2] 2b 2e [2] 16 }

  condition:
    any of them
}