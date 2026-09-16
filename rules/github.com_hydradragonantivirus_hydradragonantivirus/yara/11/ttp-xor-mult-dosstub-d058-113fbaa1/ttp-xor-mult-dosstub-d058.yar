rule TTP_XOR_MULT_DOSStub_d058 {
  strings:
    $key_d058 = { 84 30 [2] f0 28 [2] b7 2a [2] f0 3b [2] be 37 [2] b2 3d [2] a5 36 [2] be 78 [2] 83 }

  condition:
    any of them
}