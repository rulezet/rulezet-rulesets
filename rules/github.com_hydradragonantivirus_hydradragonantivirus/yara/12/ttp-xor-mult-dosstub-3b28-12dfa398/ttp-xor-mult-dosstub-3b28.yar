rule TTP_XOR_MULT_DOSStub_3b28 {
  strings:
    $key_3b28 = { 6f 40 [2] 1b 58 [2] 5c 5a [2] 1b 4b [2] 55 47 [2] 59 4d [2] 4e 46 [2] 55 08 [2] 68 }

  condition:
    any of them
}