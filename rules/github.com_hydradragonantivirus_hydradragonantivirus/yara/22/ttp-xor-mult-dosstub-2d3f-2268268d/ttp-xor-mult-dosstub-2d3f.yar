rule TTP_XOR_MULT_DOSStub_2d3f {
  strings:
    $key_2d3f = { 79 57 [2] 0d 4f [2] 4a 4d [2] 0d 5c [2] 43 50 [2] 4f 5a [2] 58 51 [2] 43 1f [2] 7e }

  condition:
    any of them
}