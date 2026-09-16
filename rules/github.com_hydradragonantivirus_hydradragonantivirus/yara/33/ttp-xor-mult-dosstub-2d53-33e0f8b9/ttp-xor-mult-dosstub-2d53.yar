rule TTP_XOR_MULT_DOSStub_2d53 {
  strings:
    $key_2d53 = { 79 3b [2] 0d 23 [2] 4a 21 [2] 0d 30 [2] 43 3c [2] 4f 36 [2] 58 3d [2] 43 73 [2] 7e }

  condition:
    any of them
}