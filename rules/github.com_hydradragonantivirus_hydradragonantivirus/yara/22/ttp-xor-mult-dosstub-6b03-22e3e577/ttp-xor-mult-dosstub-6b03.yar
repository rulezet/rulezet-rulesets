rule TTP_XOR_MULT_DOSStub_6b03 {
  strings:
    $key_6b03 = { 3f 6b [2] 4b 73 [2] 0c 71 [2] 4b 60 [2] 05 6c [2] 09 66 [2] 1e 6d [2] 05 23 [2] 38 }

  condition:
    any of them
}