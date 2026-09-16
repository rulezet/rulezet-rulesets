rule TTP_XOR_MULT_DOSStub_517a {
  strings:
    $key_517a = { 05 12 [2] 71 0a [2] 36 08 [2] 71 19 [2] 3f 15 [2] 33 1f [2] 24 14 [2] 3f 5a [2] 02 }

  condition:
    any of them
}