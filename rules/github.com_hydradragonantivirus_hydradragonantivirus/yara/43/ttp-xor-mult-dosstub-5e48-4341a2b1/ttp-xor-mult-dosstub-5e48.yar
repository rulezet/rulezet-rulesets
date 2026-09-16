rule TTP_XOR_MULT_DOSStub_5e48 {
  strings:
    $key_5e48 = { 0a 20 [2] 7e 38 [2] 39 3a [2] 7e 2b [2] 30 27 [2] 3c 2d [2] 2b 26 [2] 30 68 [2] 0d }

  condition:
    any of them
}