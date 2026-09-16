rule TTP_XOR_MULT_DOSStub_2023 {
  strings:
    $key_2023 = { 74 4b [2] 00 53 [2] 47 51 [2] 00 40 [2] 4e 4c [2] 42 46 [2] 55 4d [2] 4e 03 [2] 73 }

  condition:
    any of them
}