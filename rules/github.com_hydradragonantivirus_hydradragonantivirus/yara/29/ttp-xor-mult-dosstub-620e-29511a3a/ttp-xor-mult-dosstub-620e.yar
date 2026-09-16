rule TTP_XOR_MULT_DOSStub_620e {
  strings:
    $key_620e = { 36 66 [2] 42 7e [2] 05 7c [2] 42 6d [2] 0c 61 [2] 00 6b [2] 17 60 [2] 0c 2e [2] 31 }

  condition:
    any of them
}