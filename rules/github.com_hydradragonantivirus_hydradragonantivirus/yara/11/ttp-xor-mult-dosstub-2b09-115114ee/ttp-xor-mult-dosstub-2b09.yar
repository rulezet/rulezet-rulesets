rule TTP_XOR_MULT_DOSStub_2b09 {
  strings:
    $key_2b09 = { 7f 61 [2] 0b 79 [2] 4c 7b [2] 0b 6a [2] 45 66 [2] 49 6c [2] 5e 67 [2] 45 29 [2] 78 }

  condition:
    any of them
}