rule TTP_XOR_MULT_DOSStub_3628 {
  strings:
    $key_3628 = { 62 40 [2] 16 58 [2] 51 5a [2] 16 4b [2] 58 47 [2] 54 4d [2] 43 46 [2] 58 08 [2] 65 }

  condition:
    any of them
}