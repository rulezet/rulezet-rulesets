rule TTP_XOR_MULT_DOSStub_1f04 {
  strings:
    $key_1f04 = { 4b 6c [2] 3f 74 [2] 78 76 [2] 3f 67 [2] 71 6b [2] 7d 61 [2] 6a 6a [2] 71 24 [2] 4c }

  condition:
    any of them
}