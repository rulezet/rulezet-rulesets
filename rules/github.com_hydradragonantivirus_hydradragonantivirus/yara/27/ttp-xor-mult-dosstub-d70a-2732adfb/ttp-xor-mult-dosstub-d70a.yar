rule TTP_XOR_MULT_DOSStub_d70a {
  strings:
    $key_d70a = { 83 62 [2] f7 7a [2] b0 78 [2] f7 69 [2] b9 65 [2] b5 6f [2] a2 64 [2] b9 2a [2] 84 }

  condition:
    any of them
}