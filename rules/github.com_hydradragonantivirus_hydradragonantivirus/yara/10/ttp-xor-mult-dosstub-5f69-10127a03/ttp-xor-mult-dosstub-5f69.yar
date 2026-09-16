rule TTP_XOR_MULT_DOSStub_5f69 {
  strings:
    $key_5f69 = { 0b 01 [2] 7f 19 [2] 38 1b [2] 7f 0a [2] 31 06 [2] 3d 0c [2] 2a 07 [2] 31 49 [2] 0c }

  condition:
    any of them
}