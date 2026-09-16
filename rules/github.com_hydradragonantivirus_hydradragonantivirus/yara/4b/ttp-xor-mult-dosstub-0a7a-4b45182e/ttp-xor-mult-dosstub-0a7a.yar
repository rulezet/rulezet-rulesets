rule TTP_XOR_MULT_DOSStub_0a7a {
  strings:
    $key_0a7a = { 5e 12 [2] 2a 0a [2] 6d 08 [2] 2a 19 [2] 64 15 [2] 68 1f [2] 7f 14 [2] 64 5a [2] 59 }

  condition:
    any of them
}