rule TTP_XOR_MULT_DOSStub_1d38 {
  strings:
    $key_1d38 = { 49 50 [2] 3d 48 [2] 7a 4a [2] 3d 5b [2] 73 57 [2] 7f 5d [2] 68 56 [2] 73 18 [2] 4e }

  condition:
    any of them
}