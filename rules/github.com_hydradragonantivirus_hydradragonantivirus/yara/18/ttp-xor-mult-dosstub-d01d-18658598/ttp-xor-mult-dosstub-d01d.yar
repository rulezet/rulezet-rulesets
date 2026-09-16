rule TTP_XOR_MULT_DOSStub_d01d {
  strings:
    $key_d01d = { 84 75 [2] f0 6d [2] b7 6f [2] f0 7e [2] be 72 [2] b2 78 [2] a5 73 [2] be 3d [2] 83 }

  condition:
    any of them
}