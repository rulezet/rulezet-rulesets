rule TTP_XOR_MULT_DOSStub_5c03 {
  strings:
    $key_5c03 = { 08 6b [2] 7c 73 [2] 3b 71 [2] 7c 60 [2] 32 6c [2] 3e 66 [2] 29 6d [2] 32 23 [2] 0f }

  condition:
    any of them
}