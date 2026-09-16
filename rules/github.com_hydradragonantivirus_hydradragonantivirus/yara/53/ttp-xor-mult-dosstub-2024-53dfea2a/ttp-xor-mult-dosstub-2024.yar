rule TTP_XOR_MULT_DOSStub_2024 {
  strings:
    $key_2024 = { 74 4c [2] 00 54 [2] 47 56 [2] 00 47 [2] 4e 4b [2] 42 41 [2] 55 4a [2] 4e 04 [2] 73 }

  condition:
    any of them
}