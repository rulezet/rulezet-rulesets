rule TTP_XOR_MULT_DOSStub_137a {
  strings:
    $key_137a = { 47 12 [2] 33 0a [2] 74 08 [2] 33 19 [2] 7d 15 [2] 71 1f [2] 66 14 [2] 7d 5a [2] 40 }

  condition:
    any of them
}