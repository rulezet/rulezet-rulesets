rule TTP_XOR_MULT_DOSStub_0f13 {
  strings:
    $key_0f13 = { 5b 7b [2] 2f 63 [2] 68 61 [2] 2f 70 [2] 61 7c [2] 6d 76 [2] 7a 7d [2] 61 33 [2] 5c }

  condition:
    any of them
}