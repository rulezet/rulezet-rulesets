rule TTP_XOR_MULT_DOSStub_1423 {
  strings:
    $key_1423 = { 40 4b [2] 34 53 [2] 73 51 [2] 34 40 [2] 7a 4c [2] 76 46 [2] 61 4d [2] 7a 03 [2] 47 }

  condition:
    any of them
}