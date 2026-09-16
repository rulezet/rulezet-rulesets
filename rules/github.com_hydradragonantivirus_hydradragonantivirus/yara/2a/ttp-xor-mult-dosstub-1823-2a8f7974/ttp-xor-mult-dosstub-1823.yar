rule TTP_XOR_MULT_DOSStub_1823 {
  strings:
    $key_1823 = { 4c 4b [2] 38 53 [2] 7f 51 [2] 38 40 [2] 76 4c [2] 7a 46 [2] 6d 4d [2] 76 03 [2] 4b }

  condition:
    any of them
}