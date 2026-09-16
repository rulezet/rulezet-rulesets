rule TTP_XOR_MULT_DOSStub_d018 {
  strings:
    $key_d018 = { 84 70 [2] f0 68 [2] b7 6a [2] f0 7b [2] be 77 [2] b2 7d [2] a5 76 [2] be 38 [2] 83 }

  condition:
    any of them
}