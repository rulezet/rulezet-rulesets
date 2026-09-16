rule TTP_XOR_MULT_DOSStub_3448 {
  strings:
    $key_3448 = { 60 20 [2] 14 38 [2] 53 3a [2] 14 2b [2] 5a 27 [2] 56 2d [2] 41 26 [2] 5a 68 [2] 67 }

  condition:
    any of them
}