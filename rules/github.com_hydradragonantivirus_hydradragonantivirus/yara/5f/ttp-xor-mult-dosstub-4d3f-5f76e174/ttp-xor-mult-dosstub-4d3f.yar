rule TTP_XOR_MULT_DOSStub_4d3f {
  strings:
    $key_4d3f = { 19 57 [2] 6d 4f [2] 2a 4d [2] 6d 5c [2] 23 50 [2] 2f 5a [2] 38 51 [2] 23 1f [2] 1e }

  condition:
    any of them
}