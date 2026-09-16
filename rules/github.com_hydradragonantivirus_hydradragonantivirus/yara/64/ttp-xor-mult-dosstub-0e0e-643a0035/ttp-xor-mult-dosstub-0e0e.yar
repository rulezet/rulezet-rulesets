rule TTP_XOR_MULT_DOSStub_0e0e {
  strings:
    $key_0e0e = { 5a 66 [2] 2e 7e [2] 69 7c [2] 2e 6d [2] 60 61 [2] 6c 6b [2] 7b 60 [2] 60 2e [2] 5d }

  condition:
    any of them
}