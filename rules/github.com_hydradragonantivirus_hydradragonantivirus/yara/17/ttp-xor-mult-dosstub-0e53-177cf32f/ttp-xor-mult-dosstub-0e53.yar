rule TTP_XOR_MULT_DOSStub_0e53 {
  strings:
    $key_0e53 = { 5a 3b [2] 2e 23 [2] 69 21 [2] 2e 30 [2] 60 3c [2] 6c 36 [2] 7b 3d [2] 60 73 [2] 5d }

  condition:
    any of them
}