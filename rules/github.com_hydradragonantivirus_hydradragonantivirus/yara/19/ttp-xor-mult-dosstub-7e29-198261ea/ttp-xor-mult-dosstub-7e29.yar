rule TTP_XOR_MULT_DOSStub_7e29 {
  strings:
    $key_7e29 = { 2a 41 [2] 5e 59 [2] 19 5b [2] 5e 4a [2] 10 46 [2] 1c 4c [2] 0b 47 [2] 10 09 [2] 2d }

  condition:
    any of them
}