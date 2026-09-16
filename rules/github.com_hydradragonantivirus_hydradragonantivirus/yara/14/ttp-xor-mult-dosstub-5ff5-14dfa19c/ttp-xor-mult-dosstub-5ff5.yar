rule TTP_XOR_MULT_DOSStub_5ff5 {
  strings:
    $key_5ff5 = { 0b 9d [2] 7f 85 [2] 38 87 [2] 7f 96 [2] 31 9a [2] 3d 90 [2] 2a 9b [2] 31 d5 [2] 0c }

  condition:
    any of them
}