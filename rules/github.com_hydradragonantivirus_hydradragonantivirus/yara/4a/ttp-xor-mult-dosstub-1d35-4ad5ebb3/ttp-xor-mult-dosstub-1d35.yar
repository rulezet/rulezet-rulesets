rule TTP_XOR_MULT_DOSStub_1d35 {
  strings:
    $key_1d35 = { 49 5d [2] 3d 45 [2] 7a 47 [2] 3d 56 [2] 73 5a [2] 7f 50 [2] 68 5b [2] 73 15 [2] 4e }

  condition:
    any of them
}