rule TTP_XOR_MULT_DOSStub_1b29 {
  strings:
    $key_1b29 = { 4f 41 [2] 3b 59 [2] 7c 5b [2] 3b 4a [2] 75 46 [2] 79 4c [2] 6e 47 [2] 75 09 [2] 48 }

  condition:
    any of them
}