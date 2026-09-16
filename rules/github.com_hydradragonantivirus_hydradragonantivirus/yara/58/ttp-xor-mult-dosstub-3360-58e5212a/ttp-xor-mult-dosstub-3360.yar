rule TTP_XOR_MULT_DOSStub_3360 {
  strings:
    $key_3360 = { 67 08 [2] 13 10 [2] 54 12 [2] 13 03 [2] 5d 0f [2] 51 05 [2] 46 0e [2] 5d 40 [2] 60 }

  condition:
    any of them
}