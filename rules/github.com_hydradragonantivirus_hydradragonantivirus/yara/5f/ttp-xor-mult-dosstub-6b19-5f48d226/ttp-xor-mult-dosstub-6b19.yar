rule TTP_XOR_MULT_DOSStub_6b19 {
  strings:
    $key_6b19 = { 3f 71 [2] 4b 69 [2] 0c 6b [2] 4b 7a [2] 05 76 [2] 09 7c [2] 1e 77 [2] 05 39 [2] 38 }

  condition:
    any of them
}