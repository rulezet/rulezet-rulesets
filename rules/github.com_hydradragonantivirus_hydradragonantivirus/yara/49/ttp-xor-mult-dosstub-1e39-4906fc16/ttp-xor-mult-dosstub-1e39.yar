rule TTP_XOR_MULT_DOSStub_1e39 {
  strings:
    $key_1e39 = { 4a 51 [2] 3e 49 [2] 79 4b [2] 3e 5a [2] 70 56 [2] 7c 5c [2] 6b 57 [2] 70 19 [2] 4d }

  condition:
    any of them
}