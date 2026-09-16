rule TTP_XOR_MULT_DOSStub_5b23 {
  strings:
    $key_5b23 = { 0f 4b [2] 7b 53 [2] 3c 51 [2] 7b 40 [2] 35 4c [2] 39 46 [2] 2e 4d [2] 35 03 [2] 08 }

  condition:
    any of them
}