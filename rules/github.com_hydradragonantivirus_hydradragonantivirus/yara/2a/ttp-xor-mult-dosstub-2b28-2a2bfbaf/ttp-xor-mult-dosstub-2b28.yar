rule TTP_XOR_MULT_DOSStub_2b28 {
  strings:
    $key_2b28 = { 7f 40 [2] 0b 58 [2] 4c 5a [2] 0b 4b [2] 45 47 [2] 49 4d [2] 5e 46 [2] 45 08 [2] 78 }

  condition:
    any of them
}