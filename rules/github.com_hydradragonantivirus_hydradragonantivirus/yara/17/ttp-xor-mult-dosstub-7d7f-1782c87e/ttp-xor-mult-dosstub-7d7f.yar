rule TTP_XOR_MULT_DOSStub_7d7f {
  strings:
    $key_7d7f = { 29 17 [2] 5d 0f [2] 1a 0d [2] 5d 1c [2] 13 10 [2] 1f 1a [2] 08 11 [2] 13 5f [2] 2e }

  condition:
    any of them
}