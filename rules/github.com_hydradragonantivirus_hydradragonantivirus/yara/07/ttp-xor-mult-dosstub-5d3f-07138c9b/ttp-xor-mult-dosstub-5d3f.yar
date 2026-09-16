rule TTP_XOR_MULT_DOSStub_5d3f {
  strings:
    $key_5d3f = { 09 57 [2] 7d 4f [2] 3a 4d [2] 7d 5c [2] 33 50 [2] 3f 5a [2] 28 51 [2] 33 1f [2] 0e }

  condition:
    any of them
}