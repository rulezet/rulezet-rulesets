rule TTP_XOR_MULT_DOSStub_560e {
  strings:
    $key_560e = { 02 66 [2] 76 7e [2] 31 7c [2] 76 6d [2] 38 61 [2] 34 6b [2] 23 60 [2] 38 2e [2] 05 }

  condition:
    any of them
}