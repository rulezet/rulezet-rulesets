rule TTP_XOR_MULT_DOSStub_d029 {
  strings:
    $key_d029 = { 84 41 [2] f0 59 [2] b7 5b [2] f0 4a [2] be 46 [2] b2 4c [2] a5 47 [2] be 09 [2] 83 }

  condition:
    any of them
}