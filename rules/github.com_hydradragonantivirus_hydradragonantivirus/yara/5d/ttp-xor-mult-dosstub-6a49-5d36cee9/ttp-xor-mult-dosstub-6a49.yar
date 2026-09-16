rule TTP_XOR_MULT_DOSStub_6a49 {
  strings:
    $key_6a49 = { 3e 21 [2] 4a 39 [2] 0d 3b [2] 4a 2a [2] 04 26 [2] 08 2c [2] 1f 27 [2] 04 69 [2] 39 }

  condition:
    any of them
}