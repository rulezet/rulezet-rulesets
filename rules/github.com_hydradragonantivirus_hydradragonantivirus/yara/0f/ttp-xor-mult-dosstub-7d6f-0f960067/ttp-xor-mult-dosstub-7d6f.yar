rule TTP_XOR_MULT_DOSStub_7d6f {
  strings:
    $key_7d6f = { 29 07 [2] 5d 1f [2] 1a 1d [2] 5d 0c [2] 13 00 [2] 1f 0a [2] 08 01 [2] 13 4f [2] 2e }

  condition:
    any of them
}