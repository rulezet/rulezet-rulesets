rule TTP_XOR_MULT_DOSStub_090e {
  strings:
    $key_090e = { 5d 66 [2] 29 7e [2] 6e 7c [2] 29 6d [2] 67 61 [2] 6b 6b [2] 7c 60 [2] 67 2e [2] 5a }

  condition:
    any of them
}