rule TTP_XOR_MULT_DOSStub_7d1f {
  strings:
    $key_7d1f = { 29 77 [2] 5d 6f [2] 1a 6d [2] 5d 7c [2] 13 70 [2] 1f 7a [2] 08 71 [2] 13 3f [2] 2e }

  condition:
    any of them
}