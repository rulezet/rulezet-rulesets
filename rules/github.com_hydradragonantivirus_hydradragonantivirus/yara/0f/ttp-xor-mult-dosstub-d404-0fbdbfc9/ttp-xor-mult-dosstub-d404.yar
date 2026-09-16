rule TTP_XOR_MULT_DOSStub_d404 {
  strings:
    $key_d404 = { 80 6c [2] f4 74 [2] b3 76 [2] f4 67 [2] ba 6b [2] b6 61 [2] a1 6a [2] ba 24 [2] 87 }

  condition:
    any of them
}