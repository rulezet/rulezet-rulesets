rule TTP_XOR_MULT_DOSStub_1e69 {
  strings:
    $key_1e69 = { 4a 01 [2] 3e 19 [2] 79 1b [2] 3e 0a [2] 70 06 [2] 7c 0c [2] 6b 07 [2] 70 49 [2] 4d }

  condition:
    any of them
}