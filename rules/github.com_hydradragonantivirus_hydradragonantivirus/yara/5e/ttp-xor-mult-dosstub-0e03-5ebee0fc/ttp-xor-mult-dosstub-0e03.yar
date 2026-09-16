rule TTP_XOR_MULT_DOSStub_0e03 {
  strings:
    $key_0e03 = { 5a 6b [2] 2e 73 [2] 69 71 [2] 2e 60 [2] 60 6c [2] 6c 66 [2] 7b 6d [2] 60 23 [2] 5d }

  condition:
    any of them
}