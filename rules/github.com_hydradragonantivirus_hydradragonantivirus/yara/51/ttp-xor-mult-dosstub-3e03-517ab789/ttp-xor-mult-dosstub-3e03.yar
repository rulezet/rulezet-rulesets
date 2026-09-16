rule TTP_XOR_MULT_DOSStub_3e03 {
  strings:
    $key_3e03 = { 6a 6b [2] 1e 73 [2] 59 71 [2] 1e 60 [2] 50 6c [2] 5c 66 [2] 4b 6d [2] 50 23 [2] 6d }

  condition:
    any of them
}