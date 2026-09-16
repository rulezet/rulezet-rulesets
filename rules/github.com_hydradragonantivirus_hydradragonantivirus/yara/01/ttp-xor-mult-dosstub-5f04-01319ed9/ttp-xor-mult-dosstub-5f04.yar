rule TTP_XOR_MULT_DOSStub_5f04 {
  strings:
    $key_5f04 = { 0b 6c [2] 7f 74 [2] 38 76 [2] 7f 67 [2] 31 6b [2] 3d 61 [2] 2a 6a [2] 31 24 [2] 0c }

  condition:
    any of them
}