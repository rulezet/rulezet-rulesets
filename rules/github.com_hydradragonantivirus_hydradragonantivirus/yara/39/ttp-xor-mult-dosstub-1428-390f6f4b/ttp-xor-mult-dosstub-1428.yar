rule TTP_XOR_MULT_DOSStub_1428 {
  strings:
    $key_1428 = { 40 40 [2] 34 58 [2] 73 5a [2] 34 4b [2] 7a 47 [2] 76 4d [2] 61 46 [2] 7a 08 [2] 47 }

  condition:
    any of them
}