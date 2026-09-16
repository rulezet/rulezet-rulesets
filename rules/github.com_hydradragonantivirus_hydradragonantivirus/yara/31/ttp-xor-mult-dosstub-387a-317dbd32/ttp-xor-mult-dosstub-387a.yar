rule TTP_XOR_MULT_DOSStub_387a {
  strings:
    $key_387a = { 6c 12 [2] 18 0a [2] 5f 08 [2] 18 19 [2] 56 15 [2] 5a 1f [2] 4d 14 [2] 56 5a [2] 6b }

  condition:
    any of them
}