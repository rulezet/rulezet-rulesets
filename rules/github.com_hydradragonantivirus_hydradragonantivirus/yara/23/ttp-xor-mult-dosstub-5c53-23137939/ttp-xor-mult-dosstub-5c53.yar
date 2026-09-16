rule TTP_XOR_MULT_DOSStub_5c53 {
  strings:
    $key_5c53 = { 08 3b [2] 7c 23 [2] 3b 21 [2] 7c 30 [2] 32 3c [2] 3e 36 [2] 29 3d [2] 32 73 [2] 0f }

  condition:
    any of them
}