rule TTP_XOR_MULT_DOSStub_6b59 {
  strings:
    $key_6b59 = { 3f 31 [2] 4b 29 [2] 0c 2b [2] 4b 3a [2] 05 36 [2] 09 3c [2] 1e 37 [2] 05 79 [2] 38 }

  condition:
    any of them
}