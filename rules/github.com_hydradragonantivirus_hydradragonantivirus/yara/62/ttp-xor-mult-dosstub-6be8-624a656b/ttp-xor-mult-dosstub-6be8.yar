rule TTP_XOR_MULT_DOSStub_6be8 {
  strings:
    $key_6be8 = { 3f 80 [2] 4b 98 [2] 0c 9a [2] 4b 8b [2] 05 87 [2] 09 8d [2] 1e 86 [2] 05 c8 [2] 38 }

  condition:
    any of them
}