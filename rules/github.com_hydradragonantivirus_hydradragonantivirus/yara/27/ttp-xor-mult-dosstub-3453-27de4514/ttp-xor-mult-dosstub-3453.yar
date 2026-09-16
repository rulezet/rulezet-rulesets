rule TTP_XOR_MULT_DOSStub_3453 {
  strings:
    $key_3453 = { 60 3b [2] 14 23 [2] 53 21 [2] 14 30 [2] 5a 3c [2] 56 36 [2] 41 3d [2] 5a 73 [2] 67 }

  condition:
    any of them
}