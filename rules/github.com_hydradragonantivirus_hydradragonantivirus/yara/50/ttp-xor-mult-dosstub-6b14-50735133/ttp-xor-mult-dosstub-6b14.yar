rule TTP_XOR_MULT_DOSStub_6b14 {
  strings:
    $key_6b14 = { 3f 7c [2] 4b 64 [2] 0c 66 [2] 4b 77 [2] 05 7b [2] 09 71 [2] 1e 7a [2] 05 34 [2] 38 }

  condition:
    any of them
}