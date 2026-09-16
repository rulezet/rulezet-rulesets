rule TTP_XOR_MULT_DOSStub_7053 {
  strings:
    $key_7053 = { 24 3b [2] 50 23 [2] 17 21 [2] 50 30 [2] 1e 3c [2] 12 36 [2] 05 3d [2] 1e 73 [2] 23 }

  condition:
    any of them
}