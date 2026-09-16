rule TTP_XOR_MULT_DOSStub_2a23 {
  strings:
    $key_2a23 = { 7e 4b [2] 0a 53 [2] 4d 51 [2] 0a 40 [2] 44 4c [2] 48 46 [2] 5f 4d [2] 44 03 [2] 79 }

  condition:
    any of them
}