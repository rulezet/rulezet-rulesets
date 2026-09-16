rule TTP_XOR_MULT_DOSStub_5028 {
  strings:
    $key_5028 = { 04 40 [2] 70 58 [2] 37 5a [2] 70 4b [2] 3e 47 [2] 32 4d [2] 25 46 [2] 3e 08 [2] 03 }

  condition:
    any of them
}