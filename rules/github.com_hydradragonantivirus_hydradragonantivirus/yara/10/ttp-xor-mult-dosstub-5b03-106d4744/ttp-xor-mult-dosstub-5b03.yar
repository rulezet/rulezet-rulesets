rule TTP_XOR_MULT_DOSStub_5b03 {
  strings:
    $key_5b03 = { 0f 6b [2] 7b 73 [2] 3c 71 [2] 7b 60 [2] 35 6c [2] 39 66 [2] 2e 6d [2] 35 23 [2] 08 }

  condition:
    any of them
}