rule TTP_XOR_MULT_DOSStub_1e03 {
  strings:
    $key_1e03 = { 4a 6b [2] 3e 73 [2] 79 71 [2] 3e 60 [2] 70 6c [2] 7c 66 [2] 6b 6d [2] 70 23 [2] 4d }

  condition:
    any of them
}