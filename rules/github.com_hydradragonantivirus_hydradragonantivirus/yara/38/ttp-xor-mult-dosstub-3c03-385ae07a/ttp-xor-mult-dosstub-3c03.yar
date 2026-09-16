rule TTP_XOR_MULT_DOSStub_3c03 {
  strings:
    $key_3c03 = { 68 6b [2] 1c 73 [2] 5b 71 [2] 1c 60 [2] 52 6c [2] 5e 66 [2] 49 6d [2] 52 23 [2] 6f }

  condition:
    any of them
}