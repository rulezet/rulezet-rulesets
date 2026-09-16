rule TTP_XOR_MULT_DOSStub_7e02 {
  strings:
    $key_7e02 = { 2a 6a [2] 5e 72 [2] 19 70 [2] 5e 61 [2] 10 6d [2] 1c 67 [2] 0b 6c [2] 10 22 [2] 2d }

  condition:
    any of them
}