rule TTP_XOR_MULT_DOSStub_7123 {
  strings:
    $key_7123 = { 25 4b [2] 51 53 [2] 16 51 [2] 51 40 [2] 1f 4c [2] 13 46 [2] 04 4d [2] 1f 03 [2] 22 }

  condition:
    any of them
}