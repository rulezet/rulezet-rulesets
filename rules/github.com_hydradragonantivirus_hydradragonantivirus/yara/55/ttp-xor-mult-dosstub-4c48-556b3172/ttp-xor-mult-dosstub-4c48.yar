rule TTP_XOR_MULT_DOSStub_4c48 {
  strings:
    $key_4c48 = { 18 20 [2] 6c 38 [2] 2b 3a [2] 6c 2b [2] 22 27 [2] 2e 2d [2] 39 26 [2] 22 68 [2] 1f }

  condition:
    any of them
}