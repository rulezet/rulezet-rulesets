rule TTP_XOR_MULT_DOSStub_7149 {
  strings:
    $key_7149 = { 25 21 [2] 51 39 [2] 16 3b [2] 51 2a [2] 1f 26 [2] 13 2c [2] 04 27 [2] 1f 69 [2] 22 }

  condition:
    any of them
}