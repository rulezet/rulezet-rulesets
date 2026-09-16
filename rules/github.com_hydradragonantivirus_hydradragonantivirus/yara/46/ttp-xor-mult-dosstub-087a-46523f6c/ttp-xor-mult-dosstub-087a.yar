rule TTP_XOR_MULT_DOSStub_087a {
  strings:
    $key_087a = { 5c 12 [2] 28 0a [2] 6f 08 [2] 28 19 [2] 66 15 [2] 6a 1f [2] 7d 14 [2] 66 5a [2] 5b }

  condition:
    any of them
}