rule TTP_XOR_MULT_DOSStub_7d0e {
  strings:
    $key_7d0e = { 29 66 [2] 5d 7e [2] 1a 7c [2] 5d 6d [2] 13 61 [2] 1f 6b [2] 08 60 [2] 13 2e [2] 2e }

  condition:
    any of them
}