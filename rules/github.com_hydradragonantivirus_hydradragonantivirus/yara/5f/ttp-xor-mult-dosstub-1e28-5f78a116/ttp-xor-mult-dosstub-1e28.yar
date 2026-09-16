rule TTP_XOR_MULT_DOSStub_1e28 {
  strings:
    $key_1e28 = { 4a 40 [2] 3e 58 [2] 79 5a [2] 3e 4b [2] 70 47 [2] 7c 4d [2] 6b 46 [2] 70 08 [2] 4d }

  condition:
    any of them
}