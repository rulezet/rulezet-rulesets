rule TTP_XOR_MULT_DOSStub_6a79 {
  strings:
    $key_6a79 = { 3e 11 [2] 4a 09 [2] 0d 0b [2] 4a 1a [2] 04 16 [2] 08 1c [2] 1f 17 [2] 04 59 [2] 39 }

  condition:
    any of them
}