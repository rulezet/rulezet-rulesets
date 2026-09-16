rule TTP_XOR_MULT_DOSStub_6be2 {
  strings:
    $key_6be2 = { 3f 8a [2] 4b 92 [2] 0c 90 [2] 4b 81 [2] 05 8d [2] 09 87 [2] 1e 8c [2] 05 c2 [2] 38 }

  condition:
    any of them
}