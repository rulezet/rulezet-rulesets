rule TTP_XOR_MULT_DOSStub_3e02 {
  strings:
    $key_3e02 = { 6a 6a [2] 1e 72 [2] 59 70 [2] 1e 61 [2] 50 6d [2] 5c 67 [2] 4b 6c [2] 50 22 [2] 6d }

  condition:
    any of them
}