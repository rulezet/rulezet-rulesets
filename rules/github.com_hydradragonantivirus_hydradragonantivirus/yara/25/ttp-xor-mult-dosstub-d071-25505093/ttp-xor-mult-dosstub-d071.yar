rule TTP_XOR_MULT_DOSStub_d071 {
  strings:
    $key_d071 = { 84 19 [2] f0 01 [2] b7 03 [2] f0 12 [2] be 1e [2] b2 14 [2] a5 1f [2] be 51 [2] 83 }

  condition:
    any of them
}