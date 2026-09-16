rule TTP_XOR_MULT_DOSStub_7113 {
  strings:
    $key_7113 = { 25 7b [2] 51 63 [2] 16 61 [2] 51 70 [2] 1f 7c [2] 13 76 [2] 04 7d [2] 1f 33 [2] 22 }

  condition:
    any of them
}