rule TTP_XOR_MULT_DOSStub_4528 {
  strings:
    $key_4528 = { 11 40 [2] 65 58 [2] 22 5a [2] 65 4b [2] 2b 47 [2] 27 4d [2] 30 46 [2] 2b 08 [2] 16 }

  condition:
    any of them
}