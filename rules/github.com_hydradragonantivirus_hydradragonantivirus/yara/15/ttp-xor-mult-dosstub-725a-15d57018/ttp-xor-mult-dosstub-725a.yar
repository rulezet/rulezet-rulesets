rule TTP_XOR_MULT_DOSStub_725a {
  strings:
    $key_725a = { 26 32 [2] 52 2a [2] 15 28 [2] 52 39 [2] 1c 35 [2] 10 3f [2] 07 34 [2] 1c 7a [2] 21 }

  condition:
    any of them
}