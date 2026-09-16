rule TTP_XOR_MULT_DOSStub_d028 {
  strings:
    $key_d028 = { 84 40 [2] f0 58 [2] b7 5a [2] f0 4b [2] be 47 [2] b2 4d [2] a5 46 [2] be 08 [2] 83 }

  condition:
    any of them
}