rule TTP_XOR_MULT_DOSStub_6328 {
  strings:
    $key_6328 = { 37 40 [2] 43 58 [2] 04 5a [2] 43 4b [2] 0d 47 [2] 01 4d [2] 16 46 [2] 0d 08 [2] 30 }

  condition:
    any of them
}