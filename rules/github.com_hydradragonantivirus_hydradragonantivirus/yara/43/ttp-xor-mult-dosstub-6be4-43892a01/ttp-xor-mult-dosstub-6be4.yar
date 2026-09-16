rule TTP_XOR_MULT_DOSStub_6be4 {
  strings:
    $key_6be4 = { 3f 8c [2] 4b 94 [2] 0c 96 [2] 4b 87 [2] 05 8b [2] 09 81 [2] 1e 8a [2] 05 c4 [2] 38 }

  condition:
    any of them
}