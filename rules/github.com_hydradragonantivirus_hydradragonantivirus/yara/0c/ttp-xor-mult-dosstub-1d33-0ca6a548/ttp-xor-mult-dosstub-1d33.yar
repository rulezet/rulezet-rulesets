rule TTP_XOR_MULT_DOSStub_1d33 {
  strings:
    $key_1d33 = { 49 5b [2] 3d 43 [2] 7a 41 [2] 3d 50 [2] 73 5c [2] 7f 56 [2] 68 5d [2] 73 13 [2] 4e }

  condition:
    any of them
}