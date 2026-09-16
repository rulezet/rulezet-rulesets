rule TTP_XOR_MULT_DOSStub_0b29 {
  strings:
    $key_0b29 = { 5f 41 [2] 2b 59 [2] 6c 5b [2] 2b 4a [2] 65 46 [2] 69 4c [2] 7e 47 [2] 65 09 [2] 58 }

  condition:
    any of them
}