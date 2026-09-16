rule TTP_XOR_MULT_DOSStub_4d6f {
  strings:
    $key_4d6f = { 19 07 [2] 6d 1f [2] 2a 1d [2] 6d 0c [2] 23 00 [2] 2f 0a [2] 38 01 [2] 23 4f [2] 1e }

  condition:
    any of them
}