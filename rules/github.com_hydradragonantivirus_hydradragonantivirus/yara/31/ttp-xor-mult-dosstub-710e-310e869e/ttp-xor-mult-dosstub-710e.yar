rule TTP_XOR_MULT_DOSStub_710e {
  strings:
    $key_710e = { 25 66 [2] 51 7e [2] 16 7c [2] 51 6d [2] 1f 61 [2] 13 6b [2] 04 60 [2] 1f 2e [2] 22 }

  condition:
    any of them
}