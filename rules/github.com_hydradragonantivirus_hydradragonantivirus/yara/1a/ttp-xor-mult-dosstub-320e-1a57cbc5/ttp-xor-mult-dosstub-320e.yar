rule TTP_XOR_MULT_DOSStub_320e {
  strings:
    $key_320e = { 66 66 [2] 12 7e [2] 55 7c [2] 12 6d [2] 5c 61 [2] 50 6b [2] 47 60 [2] 5c 2e [2] 61 }

  condition:
    any of them
}