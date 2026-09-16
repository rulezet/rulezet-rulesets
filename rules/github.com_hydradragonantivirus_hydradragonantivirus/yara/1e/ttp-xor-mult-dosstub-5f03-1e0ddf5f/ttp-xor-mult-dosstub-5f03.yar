rule TTP_XOR_MULT_DOSStub_5f03 {
  strings:
    $key_5f03 = { 0b 6b [2] 7f 73 [2] 38 71 [2] 7f 60 [2] 31 6c [2] 3d 66 [2] 2a 6d [2] 31 23 [2] 0c }

  condition:
    any of them
}