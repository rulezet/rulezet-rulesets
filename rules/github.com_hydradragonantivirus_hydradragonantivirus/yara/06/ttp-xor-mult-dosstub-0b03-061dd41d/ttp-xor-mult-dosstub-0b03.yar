rule TTP_XOR_MULT_DOSStub_0b03 {
  strings:
    $key_0b03 = { 5f 6b [2] 2b 73 [2] 6c 71 [2] 2b 60 [2] 65 6c [2] 69 66 [2] 7e 6d [2] 65 23 [2] 58 }

  condition:
    any of them
}