rule TTP_XOR_MULT_DOSStub_6a03 {
  strings:
    $key_6a03 = { 3e 6b [2] 4a 73 [2] 0d 71 [2] 4a 60 [2] 04 6c [2] 08 66 [2] 1f 6d [2] 04 23 [2] 39 }

  condition:
    any of them
}