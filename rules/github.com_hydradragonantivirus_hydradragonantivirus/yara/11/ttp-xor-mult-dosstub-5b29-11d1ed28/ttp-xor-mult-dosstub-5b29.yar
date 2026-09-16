rule TTP_XOR_MULT_DOSStub_5b29 {
  strings:
    $key_5b29 = { 0f 41 [2] 7b 59 [2] 3c 5b [2] 7b 4a [2] 35 46 [2] 39 4c [2] 2e 47 [2] 35 09 [2] 08 }

  condition:
    any of them
}