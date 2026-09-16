rule TTP_XOR_MULT_DOSStub_3416 {
  strings:
    $key_3416 = { 60 7e [2] 14 66 [2] 53 64 [2] 14 75 [2] 5a 79 [2] 56 73 [2] 41 78 [2] 5a 36 [2] 67 }

  condition:
    any of them
}