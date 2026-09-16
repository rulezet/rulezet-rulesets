rule TTP_XOR_MULT_DOSStub_510e {
  strings:
    $key_510e = { 05 66 [2] 71 7e [2] 36 7c [2] 71 6d [2] 3f 61 [2] 33 6b [2] 24 60 [2] 3f 2e [2] 02 }

  condition:
    any of them
}