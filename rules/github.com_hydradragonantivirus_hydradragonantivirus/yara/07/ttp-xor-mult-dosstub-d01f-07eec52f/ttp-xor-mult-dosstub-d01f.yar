rule TTP_XOR_MULT_DOSStub_d01f {
  strings:
    $key_d01f = { 84 77 [2] f0 6f [2] b7 6d [2] f0 7c [2] be 70 [2] b2 7a [2] a5 71 [2] be 3f [2] 83 }

  condition:
    any of them
}