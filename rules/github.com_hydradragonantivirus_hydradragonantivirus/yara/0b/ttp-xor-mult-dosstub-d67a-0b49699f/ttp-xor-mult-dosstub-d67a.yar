rule TTP_XOR_MULT_DOSStub_d67a {
  strings:
    $key_d67a = { 82 12 [2] f6 0a [2] b1 08 [2] f6 19 [2] b8 15 [2] b4 1f [2] a3 14 [2] b8 5a [2] 85 }

  condition:
    any of them
}