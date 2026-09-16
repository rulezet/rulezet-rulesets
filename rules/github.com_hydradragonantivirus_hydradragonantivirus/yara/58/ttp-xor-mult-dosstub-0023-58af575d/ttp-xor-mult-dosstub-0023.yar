rule TTP_XOR_MULT_DOSStub_0023 {
  strings:
    $key_0023 = { 54 4b [2] 20 53 [2] 67 51 [2] 20 40 [2] 6e 4c [2] 62 46 [2] 75 4d [2] 6e 03 [2] 53 }

  condition:
    any of them
}