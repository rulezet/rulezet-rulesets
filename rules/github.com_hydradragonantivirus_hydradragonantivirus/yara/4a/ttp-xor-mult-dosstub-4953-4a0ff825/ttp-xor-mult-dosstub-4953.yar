rule TTP_XOR_MULT_DOSStub_4953 {
  strings:
    $key_4953 = { 1d 3b [2] 69 23 [2] 2e 21 [2] 69 30 [2] 27 3c [2] 2b 36 [2] 3c 3d [2] 27 73 [2] 1a }

  condition:
    any of them
}