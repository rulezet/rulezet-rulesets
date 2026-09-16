rule TTP_XOR_MULT_DOSStub_d004 {
  strings:
    $key_d004 = { 84 6c [2] f0 74 [2] b7 76 [2] f0 67 [2] be 6b [2] b2 61 [2] a5 6a [2] be 24 [2] 83 }

  condition:
    any of them
}