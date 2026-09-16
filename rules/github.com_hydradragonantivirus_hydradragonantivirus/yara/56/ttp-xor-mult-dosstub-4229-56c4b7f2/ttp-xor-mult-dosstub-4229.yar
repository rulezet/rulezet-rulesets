rule TTP_XOR_MULT_DOSStub_4229 {
  strings:
    $key_4229 = { 16 41 [2] 62 59 [2] 25 5b [2] 62 4a [2] 2c 46 [2] 20 4c [2] 37 47 [2] 2c 09 [2] 11 }

  condition:
    any of them
}