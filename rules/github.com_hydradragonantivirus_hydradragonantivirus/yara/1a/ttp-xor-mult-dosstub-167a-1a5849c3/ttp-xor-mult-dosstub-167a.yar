rule TTP_XOR_MULT_DOSStub_167a {
  strings:
    $key_167a = { 42 12 [2] 36 0a [2] 71 08 [2] 36 19 [2] 78 15 [2] 74 1f [2] 63 14 [2] 78 5a [2] 45 }

  condition:
    any of them
}