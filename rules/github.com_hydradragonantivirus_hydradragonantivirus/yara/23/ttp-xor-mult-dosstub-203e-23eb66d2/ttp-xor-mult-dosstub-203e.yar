rule TTP_XOR_MULT_DOSStub_203e {
  strings:
    $key_203e = { 74 56 [2] 00 4e [2] 47 4c [2] 00 5d [2] 4e 51 [2] 42 5b [2] 55 50 [2] 4e 1e [2] 73 }

  condition:
    any of them
}