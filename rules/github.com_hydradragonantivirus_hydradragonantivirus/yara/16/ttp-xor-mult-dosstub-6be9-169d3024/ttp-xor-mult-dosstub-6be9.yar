rule TTP_XOR_MULT_DOSStub_6be9 {
  strings:
    $key_6be9 = { 3f 81 [2] 4b 99 [2] 0c 9b [2] 4b 8a [2] 05 86 [2] 09 8c [2] 1e 87 [2] 05 c9 [2] 38 }

  condition:
    any of them
}