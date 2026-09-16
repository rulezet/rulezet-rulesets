rule TTP_XOR_MULT_DOSStub_3b23 {
  strings:
    $key_3b23 = { 6f 4b [2] 1b 53 [2] 5c 51 [2] 1b 40 [2] 55 4c [2] 59 46 [2] 4e 4d [2] 55 03 [2] 68 }

  condition:
    any of them
}