rule TTP_XOR_MULT_DOSStub_1123 {
  strings:
    $key_1123 = { 45 4b [2] 31 53 [2] 76 51 [2] 31 40 [2] 7f 4c [2] 73 46 [2] 64 4d [2] 7f 03 [2] 42 }

  condition:
    any of them
}