rule TTP_XOR_MULT_DOSStub_7979 {
  strings:
    $key_7979 = { 2d 11 [2] 59 09 [2] 1e 0b [2] 59 1a [2] 17 16 [2] 1b 1c [2] 0c 17 [2] 17 59 [2] 2a }

  condition:
    any of them
}