rule TTP_XOR_MULT_DOSStub_7d2f {
  strings:
    $key_7d2f = { 29 47 [2] 5d 5f [2] 1a 5d [2] 5d 4c [2] 13 40 [2] 1f 4a [2] 08 41 [2] 13 0f [2] 2e }

  condition:
    any of them
}