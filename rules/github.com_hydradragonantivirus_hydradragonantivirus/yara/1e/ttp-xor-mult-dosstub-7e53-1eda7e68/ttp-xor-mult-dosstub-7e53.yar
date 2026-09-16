rule TTP_XOR_MULT_DOSStub_7e53 {
  strings:
    $key_7e53 = { 2a 3b [2] 5e 23 [2] 19 21 [2] 5e 30 [2] 10 3c [2] 1c 36 [2] 0b 3d [2] 10 73 [2] 2d }

  condition:
    any of them
}