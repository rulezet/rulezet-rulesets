rule TTP_XOR_MULT_DOSStub_d06f {
  strings:
    $key_d06f = { 84 07 [2] f0 1f [2] b7 1d [2] f0 0c [2] be 00 [2] b2 0a [2] a5 01 [2] be 4f [2] 83 }

  condition:
    any of them
}