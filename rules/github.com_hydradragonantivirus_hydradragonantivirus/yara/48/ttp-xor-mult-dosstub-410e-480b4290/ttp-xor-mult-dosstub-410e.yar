rule TTP_XOR_MULT_DOSStub_410e {
  strings:
    $key_410e = { 15 66 [2] 61 7e [2] 26 7c [2] 61 6d [2] 2f 61 [2] 23 6b [2] 34 60 [2] 2f 2e [2] 12 }

  condition:
    any of them
}