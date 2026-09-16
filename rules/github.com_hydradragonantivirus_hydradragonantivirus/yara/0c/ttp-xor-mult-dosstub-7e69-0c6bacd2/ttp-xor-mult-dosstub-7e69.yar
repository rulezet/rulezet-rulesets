rule TTP_XOR_MULT_DOSStub_7e69 {
  strings:
    $key_7e69 = { 2a 01 [2] 5e 19 [2] 19 1b [2] 5e 0a [2] 10 06 [2] 1c 0c [2] 0b 07 [2] 10 49 [2] 2d }

  condition:
    any of them
}