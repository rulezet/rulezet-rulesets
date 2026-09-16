rule TTP_XOR_MULT_DOSStub_2803 {
  strings:
    $key_2803 = { 7c 6b [2] 08 73 [2] 4f 71 [2] 08 60 [2] 46 6c [2] 4a 66 [2] 5d 6d [2] 46 23 [2] 7b }

  condition:
    any of them
}