rule TTP_XOR_MULT_DOSStub_2823 {
  strings:
    $key_2823 = { 7c 4b [2] 08 53 [2] 4f 51 [2] 08 40 [2] 46 4c [2] 4a 46 [2] 5d 4d [2] 46 03 [2] 7b }

  condition:
    any of them
}