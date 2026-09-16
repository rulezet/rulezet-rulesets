rule TTP_XOR_MULT_DOSStub_0553 {
  strings:
    $key_0553 = { 51 3b [2] 25 23 [2] 62 21 [2] 25 30 [2] 6b 3c [2] 67 36 [2] 70 3d [2] 6b 73 [2] 56 }

  condition:
    any of them
}