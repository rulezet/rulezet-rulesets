rule TTP_XOR_MULT_DOSStub_d771 {
  strings:
    $key_d771 = { 83 19 [2] f7 01 [2] b0 03 [2] f7 12 [2] b9 1e [2] b5 14 [2] a2 1f [2] b9 51 [2] 84 }

  condition:
    any of them
}