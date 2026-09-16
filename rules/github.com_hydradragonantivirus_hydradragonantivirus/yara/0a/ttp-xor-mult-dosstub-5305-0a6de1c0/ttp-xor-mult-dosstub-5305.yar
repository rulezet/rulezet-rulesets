rule TTP_XOR_MULT_DOSStub_5305 {
  strings:
    $key_5305 = { 07 6d [2] 73 75 [2] 34 77 [2] 73 66 [2] 3d 6a [2] 31 60 [2] 26 6b [2] 3d 25 [2] 00 }

  condition:
    any of them
}