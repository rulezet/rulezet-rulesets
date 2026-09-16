rule TTP_XOR_MULT_DOSStub_6b02 {
  strings:
    $key_6b02 = { 3f 6a [2] 4b 72 [2] 0c 70 [2] 4b 61 [2] 05 6d [2] 09 67 [2] 1e 6c [2] 05 22 [2] 38 }

  condition:
    any of them
}