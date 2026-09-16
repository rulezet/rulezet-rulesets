rule TTP_XOR_MULT_DOSStub_6a48 {
  strings:
    $key_6a48 = { 3e 20 [2] 4a 38 [2] 0d 3a [2] 4a 2b [2] 04 27 [2] 08 2d [2] 1f 26 [2] 04 68 [2] 39 }

  condition:
    any of them
}