rule TTP_XOR_MULT_DOSStub_6b62 {
  strings:
    $key_6b62 = { 3f 0a [2] 4b 12 [2] 0c 10 [2] 4b 01 [2] 05 0d [2] 09 07 [2] 1e 0c [2] 05 42 [2] 38 }

  condition:
    any of them
}