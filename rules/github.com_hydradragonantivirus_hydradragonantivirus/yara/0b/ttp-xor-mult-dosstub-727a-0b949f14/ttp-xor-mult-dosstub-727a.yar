rule TTP_XOR_MULT_DOSStub_727a {
  strings:
    $key_727a = { 26 12 [2] 52 0a [2] 15 08 [2] 52 19 [2] 1c 15 [2] 10 1f [2] 07 14 [2] 1c 5a [2] 21 }

  condition:
    any of them
}