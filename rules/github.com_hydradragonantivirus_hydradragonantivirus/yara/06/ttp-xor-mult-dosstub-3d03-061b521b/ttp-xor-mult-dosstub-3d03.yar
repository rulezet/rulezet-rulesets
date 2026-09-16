rule TTP_XOR_MULT_DOSStub_3d03 {
  strings:
    $key_3d03 = { 69 6b [2] 1d 73 [2] 5a 71 [2] 1d 60 [2] 53 6c [2] 5f 66 [2] 48 6d [2] 53 23 [2] 6e }

  condition:
    any of them
}