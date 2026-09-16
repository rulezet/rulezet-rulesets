rule TTP_XOR_MULT_DOSStub_1167 {
  strings:
    $key_1167 = { 45 0f [2] 31 17 [2] 76 15 [2] 31 04 [2] 7f 08 [2] 73 02 [2] 64 09 [2] 7f 47 [2] 42 }

  condition:
    any of them
}