rule TTP_XOR_MULT_DOSStub_6f03 {
  strings:
    $key_6f03 = { 3b 6b [2] 4f 73 [2] 08 71 [2] 4f 60 [2] 01 6c [2] 0d 66 [2] 1a 6d [2] 01 23 [2] 3c }

  condition:
    any of them
}