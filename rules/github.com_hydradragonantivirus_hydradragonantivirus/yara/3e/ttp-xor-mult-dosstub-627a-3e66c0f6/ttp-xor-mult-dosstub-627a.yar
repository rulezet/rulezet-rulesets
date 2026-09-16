rule TTP_XOR_MULT_DOSStub_627a {
  strings:
    $key_627a = { 36 12 [2] 42 0a [2] 05 08 [2] 42 19 [2] 0c 15 [2] 00 1f [2] 17 14 [2] 0c 5a [2] 31 }

  condition:
    any of them
}