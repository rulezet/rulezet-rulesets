rule TTP_XOR_MULT_DOSStub_d053 {
  strings:
    $key_d053 = { 84 3b [2] f0 23 [2] b7 21 [2] f0 30 [2] be 3c [2] b2 36 [2] a5 3d [2] be 73 [2] 83 }

  condition:
    any of them
}