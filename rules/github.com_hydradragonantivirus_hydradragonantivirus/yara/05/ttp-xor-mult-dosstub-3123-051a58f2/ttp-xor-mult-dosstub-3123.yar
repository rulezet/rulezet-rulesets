rule TTP_XOR_MULT_DOSStub_3123 {
  strings:
    $key_3123 = { 65 4b [2] 11 53 [2] 56 51 [2] 11 40 [2] 5f 4c [2] 53 46 [2] 44 4d [2] 5f 03 [2] 62 }

  condition:
    any of them
}