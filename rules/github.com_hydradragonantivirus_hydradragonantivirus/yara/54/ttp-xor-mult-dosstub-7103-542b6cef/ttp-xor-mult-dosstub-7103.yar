rule TTP_XOR_MULT_DOSStub_7103 {
  strings:
    $key_7103 = { 25 6b [2] 51 73 [2] 16 71 [2] 51 60 [2] 1f 6c [2] 13 66 [2] 04 6d [2] 1f 23 [2] 22 }

  condition:
    any of them
}