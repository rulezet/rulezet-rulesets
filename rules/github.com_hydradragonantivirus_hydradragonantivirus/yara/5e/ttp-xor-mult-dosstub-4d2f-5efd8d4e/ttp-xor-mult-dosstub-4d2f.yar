rule TTP_XOR_MULT_DOSStub_4d2f {
  strings:
    $key_4d2f = { 19 47 [2] 6d 5f [2] 2a 5d [2] 6d 4c [2] 23 40 [2] 2f 4a [2] 38 41 [2] 23 0f [2] 1e }

  condition:
    any of them
}