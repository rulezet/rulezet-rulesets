rule TTP_XOR_MULT_DOSStub_252e {
  strings:
    $key_252e = { 71 46 [2] 05 5e [2] 42 5c [2] 05 4d [2] 4b 41 [2] 47 4b [2] 50 40 [2] 4b 0e [2] 76 }

  condition:
    any of them
}