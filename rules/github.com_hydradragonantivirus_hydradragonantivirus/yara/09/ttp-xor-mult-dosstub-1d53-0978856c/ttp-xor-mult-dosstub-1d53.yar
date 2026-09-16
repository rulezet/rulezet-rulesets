rule TTP_XOR_MULT_DOSStub_1d53 {
  strings:
    $key_1d53 = { 49 3b [2] 3d 23 [2] 7a 21 [2] 3d 30 [2] 73 3c [2] 7f 36 [2] 68 3d [2] 73 73 [2] 4e }

  condition:
    any of them
}