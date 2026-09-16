rule TTP_XOR_MULT_DOSStub_d0f2 {
  strings:
    $key_d0f2 = { 84 9a [2] f0 82 [2] b7 80 [2] f0 91 [2] be 9d [2] b2 97 [2] a5 9c [2] be d2 [2] 83 }

  condition:
    any of them
}